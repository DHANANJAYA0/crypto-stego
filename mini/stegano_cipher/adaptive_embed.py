from __future__ import annotations

from typing import List, Tuple

import numpy as np

from .image_utils import Block, split_blocks, block_variance


def rank_blocks_by_variance(channel: np.ndarray, block_size: int = 8) -> List[Tuple[Block, float]]:
    blocks = split_blocks(channel, block_size=block_size)
    ranked = [ (pos, block_variance(blk)) for pos, blk in blocks ]
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def choose_channel_for_block(Y_blk: np.ndarray, Cb_blk: np.ndarray, Cr_blk: np.ndarray) -> str:
    """Choose channel with highest local variance for adaptive embedding."""
    vars = {
        "Y": float(np.var(Y_blk)),
        "Cb": float(np.var(Cb_blk)),
        "Cr": float(np.var(Cr_blk)),
    }
    # Prefer luminance in ties since it has more perceptual room
    return max(vars.items(), key=lambda kv: (kv[1], 1 if kv[0] == "Y" else 0))[0]