# ============================================================
# stego.py
# Main steganography engine
# Cost function + NC-LSBM embedding + Encode + Decode
# ============================================================

import numpy as np
from PIL import Image
import scipy.ndimage
import os
import struct

from payload import prepare_payload, recover_payload

def compute_cost_map(pixels):
    """
    Computes the modification cost for every pixel-channel.

    Parameters:
        pixels : numpy array of shape (height, width, 3)
                 values 0-255 for R, G, B channels

    Returns:
        cost_map : numpy array of shape (height, width, 3)
                   one cost value per pixel per channel
                   lower = safer to modify
    """

    height, width, channels = pixels.shape

    pixels_float = pixels.astype(np.float64)

    cost_map = np.zeros((height, width, channels))

    for ch in range(channels):

        channel = pixels_float[:, :, ch]

        # ── Measurement 1: Local Variance ─────────────────
        local_mean = scipy.ndimage.uniform_filter(
            channel, size=5, mode='reflect'
        )

        local_mean_sq = scipy.ndimage.uniform_filter(
            channel ** 2, size=5, mode='reflect'
        )

        local_variance = local_mean_sq - local_mean ** 2

        local_variance = np.maximum(local_variance, 0)

        # ── Measurement 2: Directional Gradients ──────────
        shifted_right = np.roll(channel, -1, axis=1)
        shifted_left  = np.roll(channel, +1, axis=1)
        horizontal_gradient = np.abs(shifted_right - shifted_left)

        shifted_down = np.roll(channel, -1, axis=0)
        shifted_up   = np.roll(channel, +1, axis=0)
        vertical_gradient = np.abs(shifted_down - shifted_up)

        min_gradient = np.minimum(horizontal_gradient, vertical_gradient)

        # ── Combine into cost ──────────────────────────────
        epsilon = 0.001

        cost_map[:, :, ch] = 1.0 / (local_variance + min_gradient + epsilon)

    return cost_map

# NOTE: Reference implementation — not called by main.py.
# main.py uses a fully vectorized version in embed_payload().
# This function demonstrates the algorithm logic for presentation/documentation.
def get_pixel_order(cost_map, password):
    """
    Determines the order in which pixels are visited for embedding.

    Parameters:
        cost_map : numpy array (height, width, 3) of costs
        password : string password

    Returns:
        ordered list of (row, col, channel) tuples
        sorted from lowest cost to highest cost
    """

    height, width, channels = cost_map.shape

    all_indices = list(np.ndindex(height, width, channels))

    costs = np.array([cost_map[r, c, ch] for r, c, ch in all_indices])

    sorted_positions = np.argsort(costs)

    ordered_indices = [all_indices[i] for i in sorted_positions]

    import hashlib
    password_hash = hashlib.sha256(password.encode()).digest()
    seed = int.from_bytes(password_hash[:4], 'big')

    rng = np.random.default_rng(seed)

    block_size = 1000
    for start in range(0, len(ordered_indices), block_size):
        end = min(start + block_size, len(ordered_indices))
        block = ordered_indices[start:end]
        rng.shuffle(block)
        ordered_indices[start:end] = block

    return ordered_indices

# NOTE: Reference implementation of NC-LSBM — not called by main.py.
# main.py uses a fully vectorized version in embed_payload().
# This file demonstrates the algorithm logic for presentation/documentation.
def nc_lsbm_embed(pixel_value, target_bit, neighbors):
    """
    NC-LSBM: Neighborhood-Consistent LSB Matching

    Parameters:
        pixel_value : current integer value (0-255)
        target_bit  : the bit we want to store (0 or 1)
        neighbors   : list of neighboring pixel values

    Returns:
        new pixel value with target_bit in its LSB
        chosen to minimize prediction residual
    """

    current_lsb = pixel_value & 1

    if current_lsb == target_bit:
        return pixel_value

    option_up   = pixel_value + 1
    option_down = pixel_value - 1

    if pixel_value == 255:
        return option_down
    if pixel_value == 0:
        return option_up

    # ── NC-LSBM Core: Neighborhood Prediction ─────────────
    if len(neighbors) == 0:
        import random
        return option_up if random.random() < 0.5 else option_down

    predicted = sum(neighbors) / len(neighbors)

    # ── The Key Decision ──────────────────────────────────
    residual_up   = abs(option_up   - predicted)
    residual_down = abs(option_down - predicted)

    if residual_down <= residual_up:
        return option_down
    else:
        return option_up


# NOTE: Reference implementation — not called by main.py.
# main.py uses a fully vectorized version in embed_payload().
# This function demonstrates the algorithm logic for presentation/documentation.
def get_neighbors(pixels, row, col, channel):
    """
    Gets the values of pixels surrounding (row, col, channel).

    Parameters:
        pixels  : full image array (height, width, 3)
        row     : row of current pixel
        col     : column of current pixel
        channel : color channel (0, 1, or 2)

    Returns:
        list of neighbor pixel values (same channel)
    """

    height, width = pixels.shape[0], pixels.shape[1]
    neighbors = []

    if row > 0:
        neighbors.append(int(pixels[row-1, col, channel]))

    if row < height - 1:
        neighbors.append(int(pixels[row+1, col, channel]))

    if col > 0:
        neighbors.append(int(pixels[row, col-1, channel]))

    if col < width - 1:
        neighbors.append(int(pixels[row, col+1, channel]))

    return neighbors

# ============================================================
# TEST - Run this file directly to test the cost function
# python stego.py
# ============================================================

if __name__ == "__main__":

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed — skipping visualization")
        exit()

    print("=" * 50)
    print("STEGO MODULE - COST FUNCTION TEST")
    print("=" * 50)

    if not os.path.exists("test_image.png"):
        print("ERROR: test_image.png not found")
        print("Please put test_image.png in this folder")
        exit()

    print("\nLoading test image...")
    image = Image.open("test_image.png").convert("RGB")
    pixels = np.array(image)
    height, width, _ = pixels.shape
    print(f"Image size: {width} x {height} pixels")

    print("\nComputing cost map...")
    print("This measures how safe each pixel is to modify")
    cost_map = compute_cost_map(pixels)

    print(f"\nCost map statistics:")
    print(f"  Minimum cost : {cost_map.min():.4f} (most safe)")
    print(f"  Maximum cost : {cost_map.max():.2f} (most dangerous)")
    print(f"  Average cost : {cost_map.mean():.4f}")

    flat_costs = cost_map[:,:,0].flatten()
    safest_indices = np.argsort(flat_costs)[:5]
    print(f"\n5 safest pixel locations (Red channel):")
    for idx in safest_indices:
        r = idx // width
        c = idx % width
        print(f"  Row {r:4d}, Col {c:4d} - cost: {flat_costs[idx]:.6f}")

    print("\nTesting NC-LSBM function...")
    test_cases = [
        (100, 1, [98, 99, 101, 100]),
        (200, 0, [202, 201, 199, 200]),
        (128, 1, [130, 131, 129, 130]),
    ]
    print(f"  {'Value':>6} {'Target':>7} {'Neighbors':<25} {'Result':>7} {'Change':>7}")
    print(f"  {'-'*55}")
    for val, bit, neighbors in test_cases:
        result = nc_lsbm_embed(val, bit, neighbors)
        change = result - val
        pred = sum(neighbors)/len(neighbors)
        print(f"  {val:>6} {bit:>7} {str(neighbors):<25} "
              f"{result:>7} {change:>+7}  "
              f"(predicted={pred:.1f})")

    print("\nGenerating cost map visualization...")

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle("Cost Map Analysis - Lower = Safer to Modify",
                 fontsize=13, fontweight='bold')

    axes[0].imshow(pixels)
    axes[0].set_title("Original Image")
    axes[0].axis('off')

    cost_display = cost_map[:, :, 0]
    cost_norm = (cost_display - cost_display.min())
    cost_norm = cost_norm / cost_norm.max()
    cost_inverted = 1 - cost_norm

    axes[1].imshow(cost_inverted, cmap='hot')
    axes[1].set_title("Cost Map (Bright = Safe to Modify)\n"
                      "Should match textured regions of image")
    axes[1].axis('off')

    threshold = np.percentile(cost_map[:,:,0], 25)
    safe_mask = cost_map[:,:,0] < threshold
    overlay = pixels.copy()
    overlay[safe_mask, 0] = overlay[safe_mask, 0] // 2
    overlay[safe_mask, 1] = np.minimum(255,
                            overlay[safe_mask, 1].astype(int) + 60)
    overlay[safe_mask, 2] = overlay[safe_mask, 2] // 2

    axes[2].imshow(overlay)
    axes[2].set_title("Safe Embedding Locations (Green)\n"
                      "Bottom 25% cost pixels highlighted")
    axes[2].axis('off')

    plt.tight_layout()
    plt.savefig("cost_map_test.png", dpi=150, bbox_inches='tight')
    print("Saved: cost_map_test.png")
    plt.show()

    print("\n" + "=" * 50)
    print("COST FUNCTION TEST COMPLETE")
    print("Check the visualization:")
    print("  Green areas should be textured regions")
    print("  (grass, trees, fabric, rough surfaces)")
    print("  NOT smooth areas like sky or plain walls")
    print("=" * 50)
