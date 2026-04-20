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

# Import our payload module
from payload import prepare_payload, recover_payload

def compute_cost_map(pixels):
    """
    Computes the modification cost for every pixel-channel.
    
    LOW cost  = safe to modify = textured region
    HIGH cost = dangerous      = smooth region
    
    We combine TWO measurements:
    
    Measurement 1 - Local variance:
        How much do the surrounding pixels vary?
        High variance = lots of different values nearby = textured = safe
        Low variance  = all similar values nearby = smooth = dangerous
    
    Measurement 2 - Minimum directional gradient:
        How much does the image change in horizontal vs vertical direction?
        We take the MINIMUM of the two.
        Why minimum? Because if EITHER direction is smooth, the pixel
        sits on or near an edge - risky to modify.
        Only if BOTH directions are complex is the pixel truly safe.
        This is the key insight from WOW paper - avoid edges,
        embed only in regions complex in ALL directions.
    
    Final cost formula:
        cost = 1 / (variance + min_gradient + epsilon)
        
        epsilon is a tiny number (0.001) that prevents division by zero
        in perfectly flat regions where variance=0 and gradient=0.
    
    Parameters:
        pixels : numpy array of shape (height, width, 3)
                 values 0-255 for R, G, B channels
    
    Returns:
        cost_map : numpy array of shape (height, width, 3)
                   one cost value per pixel per channel
                   lower = safer to modify
    """
    
    height, width, channels = pixels.shape
    
    # Convert to float for precise calculations
    # Without this, integer arithmetic causes rounding errors
    pixels_float = pixels.astype(np.float64)
    
    # We will build the cost map channel by channel
    # Shape: (height, width, 3) - same shape as pixels
    cost_map = np.zeros((height, width, channels))
    
    for ch in range(channels):  # ch = 0 (Red), 1 (Green), 2 (Blue)
        
        # Get this channel as a 2D array
        # Shape: (height, width)
        channel = pixels_float[:, :, ch]
        
        # ── Measurement 1: Local Variance ─────────────────
        # 
        # Variance measures how spread out the values are
        # in a small window around each pixel.
        #
        # For a 5x5 window around pixel (row, col):
        #   1. Compute the average of all 25 pixel values
        #   2. For each pixel, compute (value - average)²
        #   3. Average those squared differences
        #   = variance
        #
        # scipy.ndimage.uniform_filter does step 1 efficiently:
        # it computes the local average for every pixel at once
        # size=5 means a 5x5 window
        
        # Local mean (average in 5x5 window around each pixel)
        local_mean = scipy.ndimage.uniform_filter(
            channel, size=5, mode='reflect'
        )
        
        # Local mean of squares
        local_mean_sq = scipy.ndimage.uniform_filter(
            channel ** 2, size=5, mode='reflect'
        )
        
        # Variance = E[X²] - E[X]²
        # This is the standard mathematical formula for variance
        # E[X²] = local_mean_sq
        # E[X]² = local_mean ** 2
        local_variance = local_mean_sq - local_mean ** 2
        
        # Variance can be very slightly negative due to floating
        # point precision - clip to 0 minimum
        local_variance = np.maximum(local_variance, 0)
        
        # ── Measurement 2: Directional Gradients ──────────
        #
        # A gradient measures how much the pixel value changes
        # as you move in a direction.
        #
        # Horizontal gradient at pixel (r, c):
        #   How different is pixel (r, c+1) from pixel (r, c-1)?
        #   = | pixels[r, c+1] - pixels[r, c-1] |
        #   Large = big horizontal change = horizontal edge or texture
        #   Small = similar values left and right = smooth horizontally
        #
        # Vertical gradient at pixel (r, c):
        #   How different is pixel (r+1, c) from pixel (r-1, c)?
        #   = | pixels[r+1, c] - pixels[r-1, c] |
        #   Large = big vertical change
        #   Small = smooth vertically
        #
        # np.roll shifts the entire array by N positions
        # np.roll(arr, -1, axis=1) shifts LEFT by 1 column
        # np.roll(arr, +1, axis=1) shifts RIGHT by 1 column
        
        # Horizontal gradient
        # shift right minus shift left = difference across 2 pixels
        shifted_right = np.roll(channel, -1, axis=1)  # pixel to the right
        shifted_left  = np.roll(channel, +1, axis=1)  # pixel to the left
        horizontal_gradient = np.abs(shifted_right - shifted_left)
        
        # Vertical gradient
        shifted_down = np.roll(channel, -1, axis=0)   # pixel below
        shifted_up   = np.roll(channel, +1, axis=0)   # pixel above
        vertical_gradient = np.abs(shifted_down - shifted_up)
        
        # Take the MINIMUM of horizontal and vertical gradients
        # This is the key WOW insight:
        # A pixel is only truly safe if it is complex in ALL directions
        # If EITHER direction is smooth (small gradient), it is risky
        # Minimum enforces "must be complex in all directions"
        min_gradient = np.minimum(horizontal_gradient, vertical_gradient)
        
        # ── Combine into cost ──────────────────────────────
        #
        # epsilon prevents division by zero
        # Without it: perfectly flat pixels (variance=0, gradient=0)
        # would cause division by zero error
        epsilon = 0.001
        
        # Cost formula:
        # High variance + high gradient → large denominator → LOW cost
        # Low variance + low gradient   → small denominator → HIGH cost
        # This is exactly what we want:
        # textured pixels get low cost (safe to modify)
        # smooth pixels get high cost (dangerous to modify)
        cost_map[:, :, ch] = 1.0 / (local_variance + min_gradient + epsilon)
    
    return cost_map

def get_pixel_order(cost_map, password):
    """
    Determines the order in which pixels are visited for embedding.
    
    Two goals:
    1. Visit cheapest (safest) pixels first - cost guided
    2. Order is determined by password - key dependent
    
    How we combine both goals:
    - Start with the cost-sorted order (cheapest first)
    - Use the password to create a random seed
    - Within groups of similar cost, shuffle using that seed
    
    Simple approach we use:
    - Sort ALL pixels by cost (cheapest first)
    - This gives us the base order
    - The password separately determines which pixels
      get embedded vs skipped (implemented in encode/decode)
    
    Parameters:
        cost_map : numpy array (height, width, 3) of costs
        password : string password
    
    Returns:
        ordered list of (row, col, channel) tuples
        sorted from lowest cost to highest cost
    """
    
    height, width, channels = cost_map.shape
    
    # Create a list of all (row, col, channel) index combinations
    # For a 100x100 image with 3 channels:
    # This creates 100 * 100 * 3 = 30,000 tuples
    
    # np.ndindex generates all index combinations efficiently
    # list() converts the generator to an actual list
    all_indices = list(np.ndindex(height, width, channels))
    
    # Get the cost for each index
    # For index (r, c, ch), cost is cost_map[r, c, ch]
    costs = np.array([cost_map[r, c, ch] for r, c, ch in all_indices])
    
    # Sort indices by cost (ascending = cheapest first)
    # np.argsort returns the positions that would sort the array
    # Example: if costs = [0.5, 0.1, 0.8]
    # argsort returns [1, 0, 2] meaning:
    # index 1 is smallest, then index 0, then index 2
    sorted_positions = np.argsort(costs)
    
    # Reorder all_indices using sorted_positions
    ordered_indices = [all_indices[i] for i in sorted_positions]
    
    # Key-dependent shuffling within cost-similar groups
    # We use the password to create a reproducible random seed
    # hashlib converts the password to a fixed-size number
    import hashlib
    password_hash = hashlib.sha256(password.encode()).digest()
    # Take first 4 bytes and convert to integer for use as seed
    seed = int.from_bytes(password_hash[:4], 'big')
    
    # Use numpy random with our seed for reproducible shuffling
    rng = np.random.default_rng(seed)
    
    # Shuffle within blocks of 1000 similar-cost pixels
    # This preserves the general cost ordering while adding
    # key-dependent variation
    block_size = 1000
    for start in range(0, len(ordered_indices), block_size):
        end = min(start + block_size, len(ordered_indices))
        block = ordered_indices[start:end]
        rng.shuffle(block)
        ordered_indices[start:end] = block
    
    return ordered_indices

def nc_lsbm_embed(pixel_value, target_bit, neighbors):
    """
    NC-LSBM: Neighborhood-Consistent LSB Matching
    
    YOUR NOVEL CONTRIBUTION - not present in HUGO, WOW, or S-UNIWARD
    
    Standard LSBM when modification is needed:
        Randomly choose between (value-1) and (value+1)
        50% chance of picking the worse option statistically
    
    Your NC-LSBM when modification is needed:
        Compute predicted value from neighbors
        Choose whichever of (value-1) or (value+1) is 
        CLOSER to the predicted value
        This minimizes prediction residual at this location
        Prediction residual = what SRM measures
        Reducing it = harder to detect
    
    Parameters:
        pixel_value : current integer value (0-255)
        target_bit  : the bit we want to store (0 or 1)
        neighbors   : list of neighboring pixel values
    
    Returns:
        new pixel value with target_bit in its LSB
        chosen to minimize prediction residual
    """
    
    # Check if modification is even needed
    # LSB of pixel_value = pixel_value % 2 = pixel_value & 1
    current_lsb = pixel_value & 1  # extracts the last bit
    
    if current_lsb == target_bit:
        # LSB already matches - no modification needed
        # Zero distortion at this location
        return pixel_value
    
    # Modification is needed - choose direction
    # Two options: go up by 1 or go down by 1
    option_up   = pixel_value + 1
    option_down = pixel_value - 1
    
    # Handle boundary cases
    # Pixel values must stay in range 0-255
    # If pixel_value = 255, option_up = 256 which is invalid
    # If pixel_value = 0, option_down = -1 which is invalid
    if pixel_value == 255:
        return option_down  # Can only go down
    if pixel_value == 0:
        return option_up    # Can only go up
    
    # ── NC-LSBM Core: Neighborhood Prediction ─────────────
    #
    # Predicted value = what value would this pixel "naturally" have
    # given the values of its surrounding pixels?
    #
    # Simple prediction: average of available neighbors
    # More sophisticated predictors exist but this is efficient
    # and sufficient for our purposes
    
    if len(neighbors) == 0:
        # No neighbors available - fall back to random choice
        # This only happens for edge pixels with no valid neighbors
        import random
        return option_up if random.random() < 0.5 else option_down
    
    # Compute predicted value as average of neighbors
    predicted = sum(neighbors) / len(neighbors)
    
    # ── The Key Decision ──────────────────────────────────
    #
    # Prediction residual = |actual_value - predicted_value|
    #
    # We want to MINIMIZE the prediction residual after modification
    # So we pick whichever option is CLOSER to the predicted value
    #
    # Example:
    #   current pixel value = 100
    #   predicted from neighbors = 98
    #   option_up = 101, option_down = 99
    #   |101 - 98| = 3
    #   |99  - 98| = 1   ← smaller residual, pick this one
    #   Result: use 99
    #
    # Standard LSBM would randomly pick 101 or 99
    # NC-LSBM always picks 99 in this case - always better
    
    residual_up   = abs(option_up   - predicted)
    residual_down = abs(option_down - predicted)
    
    if residual_down <= residual_up:
        return option_down
    else:
        return option_up


def get_neighbors(pixels, row, col, channel):
    """
    Gets the values of pixels surrounding (row, col, channel).
    
    We use the 4 directly adjacent pixels:
    - pixel above    (row-1, col)
    - pixel below    (row+1, col)
    - pixel to left  (row, col-1)
    - pixel to right (row, col+1)
    
    Only includes neighbors that are within image bounds.
    Edge pixels have fewer than 4 neighbors - that is fine.
    
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
    
    # Check each of the 4 directions
    # Only add if within image boundaries
    
    if row > 0:           # pixel above exists
        neighbors.append(int(pixels[row-1, col, channel]))
    
    if row < height - 1:  # pixel below exists
        neighbors.append(int(pixels[row+1, col, channel]))
    
    if col > 0:           # pixel to the left exists
        neighbors.append(int(pixels[row, col-1, channel]))
    
    if col < width - 1:   # pixel to the right exists
        neighbors.append(int(pixels[row, col+1, channel]))
    
    return neighbors

# ============================================================
# TEST - Run this file directly to test the cost function
# python stego.py
# ============================================================

if __name__ == "__main__":
    
    import matplotlib.pyplot as plt
    
    print("=" * 50)
    print("STEGO MODULE - COST FUNCTION TEST")
    print("=" * 50)
    
    # Load test image
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
    
    # Statistics
    print(f"\nCost map statistics:")
    print(f"  Minimum cost : {cost_map.min():.4f} (most safe)")
    print(f"  Maximum cost : {cost_map.max():.2f} (most dangerous)")
    print(f"  Average cost : {cost_map.mean():.4f}")
    
    # Find the 10 safest pixels
    flat_costs = cost_map[:,:,0].flatten()
    safest_indices = np.argsort(flat_costs)[:5]
    print(f"\n5 safest pixel locations (Red channel):")
    for idx in safest_indices:
        r = idx // width
        c = idx % width
        print(f"  Row {r:4d}, Col {c:4d} - cost: {flat_costs[idx]:.6f}")
    
    # Test NC-LSBM
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
    
    # Visualize cost map
    print("\nGenerating cost map visualization...")
    
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle("Cost Map Analysis - Lower = Safer to Modify",
                 fontsize=13, fontweight='bold')
    
    # Original image
    axes[0].imshow(pixels)
    axes[0].set_title("Original Image")
    axes[0].axis('off')
    
    # Cost map (Red channel) - inverted so bright = safe
    # We invert because bright is easier to interpret as "safe"
    cost_display = cost_map[:, :, 0]
    # Normalize to 0-1 range for display
    cost_norm = (cost_display - cost_display.min())
    cost_norm = cost_norm / cost_norm.max()
    # Invert: 1 - normalized so bright = LOW cost = SAFE
    cost_inverted = 1 - cost_norm
    
    axes[1].imshow(cost_inverted, cmap='hot')
    axes[1].set_title("Cost Map (Bright = Safe to Modify)\n"
                      "Should match textured regions of image")
    axes[1].axis('off')
    
    # Side by side comparison
    # Show just the safe pixels (cost below threshold)
    threshold = np.percentile(cost_map[:,:,0], 25)
    safe_mask = cost_map[:,:,0] < threshold
    overlay = pixels.copy()
    # Tint safe pixels green
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




