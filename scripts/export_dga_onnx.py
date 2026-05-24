#!/usr/bin/env python3
"""
Export Reynier/dga-cnn (PyTorch) to ONNX for embedding in the mailhook-ai binary.

Architecture inlined from Reynier/dga-cnn model.py (MIT licence).
CHARS / encoding must stay in sync with encodeDomainChars() in onnx_ai.go.

Usage:
    python3 scripts/export_dga_onnx.py --outdir app/scanners/models/dga-cnn
"""
import argparse
import string
import sys
from pathlib import Path

import torch
import torch.nn as nn

# ── Model definition (from Reynier/dga-cnn model.py) ──────────────────────────
CHARS = string.ascii_lowercase + string.digits + "-._"
VOCAB_SIZE = len(CHARS) + 1   # 40  (0 = padding)
MAXLEN = 75


class DGACNN(nn.Module):
    def __init__(self, vocab_size=VOCAB_SIZE, embedding_dim=32, num_classes=2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(embedding_dim, 64, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(2)
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Linear(64 * (MAXLEN // 2), num_classes)

    def forward(self, x):
        x = self.embedding(x).transpose(1, 2)
        x = self.pool(self.relu(self.conv1(x)))
        x = x.view(x.size(0), -1)
        x = self.dropout(x)
        return self.fc(x)


# ── Export ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", required=True, help="Output directory for model.onnx")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("Installing huggingface_hub...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "huggingface_hub"])
        from huggingface_hub import hf_hub_download

    print("Downloading Reynier/dga-cnn weights from HuggingFace...")
    pth_path = hf_hub_download("Reynier/dga-cnn", "dga_cnn_model_1M.pth")

    model = DGACNN()
    model.load_state_dict(torch.load(pth_path, map_location="cpu", weights_only=True))
    model.eval()

    dummy = torch.zeros(1, MAXLEN, dtype=torch.long)
    out_path = outdir / "model.onnx"

    # dynamo=False forces the legacy TorchScript exporter: recent torch defaults
    # to the dynamo exporter (which pulls in onnxscript and may rename graph I/O),
    # but onnx_ai.go binds the exact tensor names below, so we need the legacy path.
    torch.onnx.export(
        model,
        dummy,
        str(out_path),
        input_names=["domain_chars"],
        output_names=["logits"],
        dynamic_axes={"domain_chars": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=18,
        dynamo=False,
    )

    size_kb = out_path.stat().st_size // 1024
    print(f"Exported: {out_path} ({size_kb} KB)")
    print(f"MAXLEN={MAXLEN}, VOCAB_SIZE={VOCAB_SIZE}")

    try:
        import onnx
        m = onnx.load(str(out_path))
        print("inputs: ", [i.name for i in m.graph.input])
        print("outputs:", [o.name for o in m.graph.output])
    except ImportError:
        print("(install onnx to verify tensor names)")


if __name__ == "__main__":
    main()
