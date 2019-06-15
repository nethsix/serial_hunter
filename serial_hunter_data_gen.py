# IMPORTANT:
# * Sequence 
#   * Considers if numbers are different from each other within a gap/distance
#     If they are within gap then, they become part of a sequence
#   * All the numbers in the an entire sample of BATCH_NUMBER_COUNT is eligible for
#     for consideration of a sequence
# * Sample
#   * A sample containing BATCH_NUMBER_COUNT of numbers
#   * It represents all the numbers pulled out during an SQL query to check for
#     sequence
#   * NOTE: The term gap is NOT related to where the sequence elements are located
#     in the sample. There is no term related to the location of sequence elements
#     in the sample

from functools import reduce

import argparse
import csv
import math
# Use pdb.set_trace() where you want to stop
import pdb
import random

parser = argparse.ArgumentParser()
parser.add_argument("--include_50000", help="Include data with 50000 samples",
                    action="store_true", default=False)
parser.add_argument("--with_pos", help="Include data with position of sequence samples",
                    action="store_true", default=False)
args = parser.parse_args()

# E.g., 817031905898 has size of 12
NUMBER_SIZE = 15
MIN_NUMBER = 10**(NUMBER_SIZE-1)
MAX_NUMBER = 10**NUMBER_SIZE
# In each time the serial_hunter runs, what is the batch size the serial_hunter is processing
# In practice, if we run the serial_hunter every 1 minute and we can expect 1000 numbers,
# then set this to 1000
BATCH_NUMBER_COUNT = 1000
DATA_SIZE = 10
# This meaans that gap up to and including is ok, e.g., if THRESHOLD_GAP = 4
# then anything between and inclusive 1, 5 (1 + 4) is considered part of sequence
THRESHOLD_GAP= 4

# If elements in sequence is greater than this then serial sequence is considered detected
THRESHOLD_SEQUENCE = 5
# If EBCDIC_MODE then a 2 digit is represented by 8-bit (4-bit for each digit)
# If not EBCDIC_MODE then a 2 digit is represented by 7-bit (7-bit can cover up to 128)
EBCDIC_MODE = True

SINGLE_SAMPLE_SIZE_50 = 50

# There are data types, and the outcome
# 1. Sequence < X, gap > Y, decision: false
# 2. Sequence < X, gap < Y, decision: false
# 3. Sequence > X, gap > Y, decision: false
# 4. Sequence > X, gap < Y, decision: false
DATA_TYPE_SIZE = 4

# Finding the sequence of expected count and extending across the largest
# distance for max_gap
#
# Example:
# max_gap = 4
# 1 + 4 = 5 (include), 1 2 3 4 5
# 5 + 4 = 9 (include), 5 6 7 8 9
# 9 + 4 = 13 (include), 9 10 11 12 13
# 13 + 4 = 17 (include), 13 14 15 16 17
#
# seq_count = 2
# First number: 1, Last number: 1 + ((2-1)*(4)) = 5, Distance = 5 - 1 = 4
#
# seq_count = 3
# First number: 1, Last number: 1 + ((3-1)*(4)) = 9, Distance = 9 - 1 = 8
#
# seq_count = 4
# First number: 1, Last number: 1 + ((4-1)*(4)) = 13, Distance = 13 - 1 = 12
def find_largest_distance_between_first_and_last_in_seq(seq_count, max_gap=THRESHOLD_GAP):
  return (seq_count-1)*max_gap

# Get random first number in sequence
# Takes into consideration min_number, max_number, and max_gap
def get_seq_start(seq_count, min_number, max_number, max_gap=THRESHOLD_GAP):
  latest_first_seq_elem = max_number - find_largest_distance_between_first_and_last_in_seq(seq_count, max_gap)
  if latest_first_seq_elem < min_number:
     raise ValueError("The distance min_number: %d and max_number: %d is not enough to support %d elements in sequence with max_gap: %d" % (min_number, max_number, seq_count, max_gap))
  # The first number in the sequence cannot be later than latest_first_seq_elem
  # This is important when latest_first_seq_elem < max_gap. Under this circumstances
  # if first number in sequence is chosen by using random distance from min_number,
  # it may choose a number that is greater than latest_first_seq_elem, and then if all
  # other elements in sequence has max_gap in between, the later numbers will go beyond max_number
  return random.randint(min_number, latest_first_seq_elem)

# Generate a sequence of numbers
# seq_count: Elements in sequence
# min_count: Min possible number in sequence
# max_count: Max possible number in sequence
# seq_pos: Where the sequence is in the position [NOT IMPLEMENTED]
#          If 3 then the sequence is 3 positions from the right, i.e., 104233, 104333, 104433, etc.
# min_gap: What is the min gap between elements in sequence, inclusive
# max_gap: What is the max gap between elements in sequence, inclusive
def generate_seq(seq_count, min_number, max_number, seq_pos=0, min_gap=1, max_gap=THRESHOLD_GAP, in_order=True):
  seq_start = get_seq_start(seq_count, min_number, max_number, max_gap)
  seq_arr = [seq_start]
  for i in range(seq_count-1):
    seq_arr.append(seq_arr[i]+random.randint(min_gap, max_gap))
  if not in_order:
    random.shuffle(seq_arr)
  return seq_arr

# Converts [0, 3, 5] to 101001, i.e., each number specifies whic the '1' bit should be
# with the bit order starting from right to left
# position_arr: an array containing the positions of where all '1' bits are
# total bit count: this determines hot many bits in total so we can pad the left or right with 0s
#                  depending on least_significant_on_left
# least_significant_on_left: Reverses the bits such bit order is left to right
def convert_position_arr_to_binary(position_arr, total_bit_count, least_significant_on_left=True):
  # The i+1 in ljust is because:
  # '1'.ljust(0, '0') returns same as '1'.ljust(1, '0')
  binary_encoded_positions = bin(reduce(lambda m, i: int('1'.ljust(i+1, '0'), 2) + m, position_arr, 0))[2:]
  padded_order_adjust_binary_encoded_positions = None
  if least_significant_on_left:
    # Reverse the binary encoded positions so that they are they are in the same order as 
    order_adjust_binary_encoded_positions = binary_encoded_positions[::-1]
    padded_order_adjust_binary_encoded_positions = order_adjust_binary_encoded_positions.ljust(total_bit_count, '0')
  else:
    order_adjust_binary_encoded_positions = binary_encoded_positions
    padded_order_adjust_binary_encoded_positions = order_adjust_binary_encoded_positions.rjust(total_bit_count, '0')
  return padded_order_adjust_binary_encoded_positions

# NOTE:
# This will generate 2 files
# * File with attack sequence of size: 12 * rows_per_attack_type
# * File with no attack of same size
def generate_sparse_head_heavy_tail_heavy_ooo_mid_combo_for_bin_class(rows_per_attack_type, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=None):
  # Permutation of:
  # * location of sequence (sparse, head-heavy, tail-heavy), x3
  # * sequence-in-mid, x2
  # * out-of-order, x2
  total_attack_type = 12
  total_rows = total_attack_type * rows_per_attack_type

  if not seq_pos:
    seq_pos = random.randint(0, single_sample_size-1)

  no_seq_filename = 'data_no_sequence_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'
  seq_filename = 'data_sequence_sparse_head_heavy_tail_heavy_ooo_mid_combo_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'

  print("Create: %s" % no_seq_filename)
  with open(no_seq_filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    # Generate no sequence
    for i in range(total_rows):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
  csv_file.close()

  print("Create: %s" % seq_filename)
  with open(seq_filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)

    # Generate sequence-not-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-not-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

  csv_file.close()

# This will generate 4 files
# * File with each attack sequence of size: 4 * rows_per_attack_type
# * File with no attack of same size
def generate_sparse_head_heavy_tail_heavy_ooo_mid_for_multi_class(rows_per_attack_type, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=None):
  # Permutation of:
  # * location of sequence (sparse, head-heavy, tail-heavy), x3
  # * sequence-in-mid, x2
  # * out-of-order, x2
  # For multi-class, the class is based on location of sequence so
  # * sparse: x4
  # * head-heavy: x4
  # * tail-heavy: x4
  total_class = 4
  total_rows = total_class * rows_per_attack_type

  if not seq_pos:
    seq_pos = random.randint(0, single_sample_size-1)

  filename = 'data_no_sequence_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'

  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    # Generate no sequence
    for i in range(total_rows):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)
  csv_file.close()

  # Generate sparse
  filename = 'data_sequence_sparse_ooo_mid_combo_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)

    # Generate sequence-not-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-not-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

  csv_file.close()

  # Generate head-heavy
  filename = 'data_sequence_head_heavy_ooo_mid_combo_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)

    # Generate sequence-not-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-not-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

  csv_file.close()

  # Generate tail-heavy
  filename = 'data_sequence_tail_heavy_ooo_mid_combo_' + str(total_rows) + '_sample_number_' + str(single_sample_size) + '.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)

    # Generate sequence-not-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-not-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, in-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

    # Generate sequence-in-mid, out-of-order
    for i in range(rows_per_attack_type):
      sa = generate_seq(seq_size, MIN_NUMBER, MAX_NUMBER, seq_pos=seq_pos, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=single_sample_size)
      writer.writerow(nsa)

  csv_file.close()


# Same like generate_seq but also returns position index
def generate_seq_with_pos_index(seq_count, min_number, max_number, seq_pos=0, min_gap=1, max_gap=THRESHOLD_GAP):
  if seq_pos == 0:
    first_part = get_seq_start(seq_count, min_number, max_number, max_gap)
    second_part_str = ""
  else:
    # Remove the first seq_pos digits because we want the sequence to happen
    # at seq_pos position from the right
    seq_num = get_seq_start(seq_count, min_number, max_number, max_gap)
    if seq_pos >= NUMBER_SIZE:
      raise ValueError("seq_pos: %d, which is the how far from the right the sequence patter happens MUST be less than NUMBER_SIZE: %d" % (seq_pos, NUMBER_SIZE))
    seq_num_str = str(seq_num)
    first_part_str = seq_num_str[0] + seq_num_str[seq_pos+1:]
    first_part = int(first_part_str)
    # Generate some random number to be appended to the truncated number. This part will be fixed
    second_part_str = (("%0" + str(seq_pos) + "d") % random.randint(0, 10**seq_pos-1))
    if (len(first_part_str) + len(second_part_str)) != NUMBER_SIZE:
      pdb.set_trace()
  first_part_arr = [first_part]
  for i in range(seq_count-1):
    first_part_arr.append(first_part_arr[i]+random.randint(min_gap, max_gap))
  return list(map(lambda x: int(str(x) + second_part_str), first_part_arr))

# Generate a set of numbers that are guaranteed to be non sequence
# Divide them into blocks that are bigger than max_gap,
# and then select numbers from blocks that are not adjacent each time
# while also avoid any blocks that contains any sequece all the time
def generate_non_seq_numbers(seq_arr, min_number, max_number, max_gap=THRESHOLD_GAP, single_sample_size=BATCH_NUMBER_COUNT):
  non_seq_numbers = []
  number_range = max_number - min_number
  last_block = math.floor(number_range/max_gap)
  # Blocks of seq that we should not pick numbers from
  # Also avoid adjacent blocks
  seq_arr_block_number_start = math.floor((seq_arr[0] - min_number)/max_gap)
  seq_arr_block_number_end = math.floor((seq_arr[-1] - min_number)/max_gap)

  # last_block_number tracks what was the last_block that we pick a number from
  # so that when picking the next number we avoid picking from the same block
  # as well as adjacent block
  last_block_number = seq_arr_block_number_start

  for i in range(single_sample_size - len(seq_arr)):
    try:
      block_number = random.randint(0, seq_arr_block_number_start-1) if random.randint(0,1) == 0 else random.randint(seq_arr_block_number_end+1, last_block)
    except:
      pdb.set_trace()
    if (block_number >= last_block_number-1) and (block_number <= last_block_number+1):
      block_number += 4
      if block_number-4 > last_block:
        block_number -= 8
        if block_number < 0:
          raise ValueError("The distance min_number: %d (block number: %d) and max_number: %d (block number: %d)with sequence from: %d (block number: %d) to: %d (block number: %d) does not have enough number range to produce numbers not in the sequence" % (min_number, 0, max_number, last_block, seq_arr[0], seq_arr_block_number_start, seq_arr[-1], seq_arr_block_number_end))
    number = min_number + random.randint(block_number*max_gap, (block_number+1)*max_gap)
    non_seq_numbers.append(number)
    last_block_number = block_number
  return non_seq_numbers

# Given a sequence, add other non-sequence numbers to create the entire sample,
# which contains BATCH_NUMBER_COUNT numbers
#ORIG def generate_seq_sparse(seq_arr, min_number, max_number, max_gap=THRESHOLD_GAP, single_sample_size=BATCH_NUMBER_COUNT):
#ORIG   sample_arr = generate_non_seq_numbers(seq_arr, min_number, max_number, max_gap, single_sample_size)
#ORIG   seq_idx_arr = []
#ORIG   seq_elem_distance = math.floor(single_sample_size/len(seq_arr))
#ORIG   for i in range(len(seq_arr)):
#ORIG     seq_idx_arr.append(i*seq_elem_distance)
#ORIG     sample_arr.insert(i*seq_elem_distance, seq_arr[i])
#ORIG   return sample_arr

# Same as generate_seq_sparse but also returns the seq index positions
def generate_seq_sparse(seq_arr, min_number, max_number, max_gap=THRESHOLD_GAP, single_sample_size=BATCH_NUMBER_COUNT, include_pos_index_arr=False):
  sample_arr = generate_non_seq_numbers(seq_arr, min_number, max_number, max_gap, single_sample_size)
  seq_idx_arr = []
  seq_elem_distance = math.floor(single_sample_size/len(seq_arr))
  for i in range(len(seq_arr)):
    seq_idx_arr.append(i*seq_elem_distance)
    sample_arr.insert(i*seq_elem_distance, seq_arr[i])
  if include_pos_index_arr:
    bin_encoded_pos_arr = list(convert_position_arr_to_binary(seq_idx_arr, single_sample_size))
    return [bin_encoded_pos_arr, sample_arr]
  else:
    return sample_arr

def generate_seq_tail_heavy(seq_arr, min_number, max_number, max_gap=THRESHOLD_GAP, single_sample_size=BATCH_NUMBER_COUNT, include_pos_index_arr=False):
  #OLD new_arr = None
  #OLD # Sequence numbers can start from this (including) this index
  #OLD halfway_idx = math.floor(single_sample_size/2)
  #OLD if (single_sample_size - halfway_idx) < len(seq_arr):
  #OLD   # There are too many seq numbers to fit into the 2nd half of sample
  #OLD   raise ValueError("Each half of the sample size should be (single_sample_size/2): %d, but len(seq_arr): %d, which is the number of sequential numbers that we want to squeeze into the tail end is greater than what half of the sample size can contain" % (halfway_idx))
  #OLD else:
  #OLD   sample_arr = generate_non_seq_numbers(seq_arr, min_number, max_number, max_gap, single_sample_size)
  #OLD   new_arr = sample_arr[0:halfway_idx]
  #OLD   to_use_no_seq_arr = sample_arr[halfway_idx:]
  #OLD   remain_space_between_seq_in_tail = single_sample_size - halfway_idx - len(seq_arr)
  #OLD   for i in seq_arr:
  #OLD     curr_usable_idx = len(new_arr)
  #OLD     # Randomly choose how far away from current elem the next number in the seq is
  #OLD     space = random.randint(0, remain_space_between_seq_in_tail)
  #OLD     new_arr += to_use_no_seq_arr[0:space]
  #OLD     to_use_no_seq_arr = to_use_no_seq_arr[space:]
  #OLD     new_arr.append(i)
  #OLD return new_arr
  return generate_seq_head_within_pct_position(seq_arr, min_number, max_number, 51, 100, max_gap, single_sample_size, include_pos_index_arr)

def generate_seq_head_heavy(seq_arr, min_number, max_number, max_gap=THRESHOLD_GAP, single_sample_size=DATA_SIZE, include_pos_index_arr=False):
  return generate_seq_head_within_pct_position(seq_arr, min_number, max_number, 0, 50, max_gap, single_sample_size, include_pos_index_arr)

def generate_seq_head_within_pct_position(seq_arr, min_number, max_number, start_pct, end_pct, max_gap=THRESHOLD_GAP, single_sample_size=DATA_SIZE, include_pos_index_arr=False):
  new_arr = None
  seq_idx_arr = []
  # Sequence numbers can start from this (including) this index
  start_idx = math.floor(start_pct*single_sample_size/100)
  end_idx = math.ceil(end_pct*single_sample_size/100)
  #pdb.set_trace()
  if (end_idx - start_idx) < len(seq_arr):
    # There are too many seq numbers to fit into the range
    raise ValueError("The space available within start_idx: %d (start_pct: %d), end_idx: %d (end_pct: %d), but len(seq_arr): %d, which is the number of sequential numbers that we want to squeeze into space avaialble" % (start_idx, start_pct, end_idx, end_pct, len(seq_arr)))
  else:
    sample_arr = generate_non_seq_numbers(seq_arr, min_number, max_number, max_gap, single_sample_size)
    new_arr = sample_arr[0:start_idx]
    to_use_no_seq_arr = sample_arr[start_idx:]
    remain_space_between_seq = end_idx - start_idx - len(seq_arr)
    # pdb.set_trace()
    for i in seq_arr:
      curr_usable_idx = len(new_arr)
      # Randomly choose how far away from current elem the next number in the seq is
      space = random.randint(0, remain_space_between_seq)
      new_arr += to_use_no_seq_arr[0:space]
      to_use_no_seq_arr = to_use_no_seq_arr[space:]
      new_arr.append(i)
      prev_seq_idx = seq_idx_arr[-1] if len(seq_idx_arr) > 0 else (start_idx-1)
      # seq_idx_arr.append(seq_idx_arr[-1] + space+1)
      seq_idx_arr.append(prev_seq_idx + space + 1)
      remain_space_between_seq -= space
    # pdb.set_trace()
    if (len(to_use_no_seq_arr) > 0):
      new_arr += to_use_no_seq_arr
  if include_pos_index_arr:
    bin_encoded_pos_arr = list(convert_position_arr_to_binary(seq_idx_arr, single_sample_size))
    return [bin_encoded_pos_arr, new_arr]
  else:
    return new_arr

# def generate_seq_start_focus(seq_arr):

# def generate_seq_middle_focus(seq_arr):

# def generate_seq_end_focus(seq_arr):

# Goal: Generate the entire BATCH_NUMBER_COUNT * NUMBER_SIZE*8-bit (EBCDIC number) 
# 
def gen_data_type_1(seq_count, min_number, max_number=10**NUMBER_SIZE, min_gap=0, max_gap=THRESHOLD_GAP):
  seq_arr = generate_seq(seq_count, min_number, max_number)
  return generate_seq_sparse(seq_arr, min_number, max_number)
  
DATE_TYPE_DATA_SIZE = int(DATA_SIZE/DATA_TYPE_SIZE)


# ROUGH

##### filename = 'data_sequence_mid_sparse_50000_sample_number_50.csv'
##### print("Create: %s" % filename)
##### with open(filename, mode='w') as csv_file:
#####   writer = csv.writer(csv_file)
#####   for i in range(50000):
#####     sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
#####     if len(str(sa[0])) < NUMBER_SIZE-1:
#####       pdb.set_trace()
#####     nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
#####     writer.writerow(nsa)
##### csv_file.close()

# DEBUG
# sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
# print("seq: %s" % sa)
# nsa = generate_non_seq_numbers(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
# print("non-seq: %s" % nsa)
sa_mid = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
# print("seq in mid: %s" % sa_mid)
# print("%s" % generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10))
# exit()


if args.with_pos:
  filename = 'data_sequence_head_heavy_500_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_sparse_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_head_heavy_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_tail_heavy_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  if args.include_50000:
    filename = 'data_sequence_sparse_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        pos_idx_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_idx_arr + nsa)
    csv_file.close()
    
    filename = 'data_sequence_head_heavy_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        pos_idx_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_idx_arr + nsa)
    csv_file.close()
    
    filename = 'data_sequence_tail_heavy_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_index_arr + nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_sparse_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_index_arr + nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_head_heavy_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_index_arr + nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_tail_heavy_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_index_arr + nsa)
    csv_file.close()
  
  filename = 'data_no_sequence_20000_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  if args.include_50000:
    filename = 'data_no_sequence_50000_sample_number_50_w_pos.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
        pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
        writer.writerow(pos_index_arr + nsa)
    csv_file.close()

  filename = 'data_sequence_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr,  nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()

  filename = 'data_no_sequence_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()

  filename = 'data_sequence_tail_heavy_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()

  filename = 'data_sequence_head_heavy_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()

  filename = 'data_sequence_mid_tail_heavy_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
 
  filename = 'data_sequence_mid_head_heavy_5_sample_number_50_w_pos.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      pos_index_arr, nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50, include_pos_index_arr=True)
      writer.writerow(pos_index_arr + nsa)
  csv_file.close()
  
else:
  filename = 'data_sequence_100.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(100):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_no_sequence_100.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(100):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_5000.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_tail_heavy_1000.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_head_heavy_tail_heavy_1500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_tail_heavy_1500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_head_heavy_tail_heavy_7500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(2500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_no_sequence_500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_no_sequence_5000.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_no_sequence_7500.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(7500):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      sa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  # Prediction check data set which is small, i.e., 5
  
  filename = 'data_sequence_5.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_no_sequence_5.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_5.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_5.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=10)
      writer.writerow(nsa)
  csv_file.close()
  
  
  # More numbers in each sample, i.e., wider vicnity between location of sequences numbers
  
  filename = 'data_sequence_sparse_500_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_500_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_5000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_5000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_5000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_mid_sparse_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_head_heavy_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_tail_heavy_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_sparse_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_sparse_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_head_heavy_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_tail_heavy_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  # Out of order (ooo) 10000
  filename = 'data_sequence_sparse_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_sparse_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_head_heavy_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_tail_heavy_ooo_10000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  # Out of order (ooo) 20000
  filename = 'data_sequence_sparse_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_head_heavy_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_tail_heavy_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_sparse_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_head_heavy_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_tail_heavy_ooo_20000_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  if args.include_50000:
    filename = 'data_sequence_sparse_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
    
    filename = 'data_sequence_head_heavy_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
    
    filename = 'data_sequence_tail_heavy_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
        nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_sparse_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_head_heavy_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
    
    filename = 'data_sequence_mid_tail_heavy_50000_sample_number_50.csv'
    print("Create: %s" % filename)
    with open(filename, mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
        nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
  
  with open('data_sequence_sparse_head_heavy_tail_heavy_1500_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_sequence_sparse_head_heavy_tail_heavy_7500_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(2500):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_no_sequence_500_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(500):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_no_sequence_5000_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5000):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_no_sequence_7500_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(7500):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_no_sequence_10000_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(10000):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  with open('data_no_sequence_20000_sample_number_50.csv', mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(20000):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  generate_sparse_head_heavy_tail_heavy_ooo_mid_combo_for_bin_class(2, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=SINGLE_SAMPLE_SIZE_50/2)
  generate_sparse_head_heavy_tail_heavy_ooo_mid_combo_for_bin_class(170, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=SINGLE_SAMPLE_SIZE_50/2)
  generate_sparse_head_heavy_tail_heavy_ooo_mid_combo_for_bin_class(500, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=SINGLE_SAMPLE_SIZE_50/2)
  generate_sparse_head_heavy_tail_heavy_ooo_mid_combo_for_bin_class(850, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=SINGLE_SAMPLE_SIZE_50/2)

  generate_sparse_head_heavy_tail_heavy_ooo_mid_for_multi_class(500, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=None)
  generate_sparse_head_heavy_tail_heavy_ooo_mid_for_multi_class(2500, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=None)
  generate_sparse_head_heavy_tail_heavy_ooo_mid_for_multi_class(3500, seq_size=THRESHOLD_SEQUENCE, single_sample_size=SINGLE_SAMPLE_SIZE_50, seq_pos=None)

  if args.include_50000:
    with open('data_no_sequence_50000_sample_number_50.csv', mode='w') as csv_file:
      writer = csv.writer(csv_file)
      for i in range(50000):
        sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
        nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
        writer.writerow(nsa)
    csv_file.close()
  
  # More numbers, prediction check data set which is small, i.e., 5
  
  filename = 'data_sequence_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_no_sequence_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(1, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_tail_heavy_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_head_heavy_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_mid_tail_heavy_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
 
  filename = 'data_sequence_mid_head_heavy_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  # Out of order (ooo)
  filename = 'data_sequence_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
  
  filename = 'data_sequence_mid_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_sparse(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_tail_heavy_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_head_heavy_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

  filename = 'data_sequence_mid_tail_heavy_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_tail_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()
 
  filename = 'data_sequence_mid_head_heavy_ooo_5_sample_number_50.csv'
  print("Create: %s" % filename)
  with open(filename, mode='w') as csv_file:
    writer = csv.writer(csv_file)
    for i in range(5):
      sa = generate_seq(5, MIN_NUMBER, MAX_NUMBER, seq_pos=5, in_order=False)
      nsa = generate_seq_head_heavy(sa, MIN_NUMBER, MAX_NUMBER, single_sample_size=50)
      writer.writerow(nsa)
  csv_file.close()

# 1. Sequence < X, gap > Y, decision: false
#for i in range(DATE_TYPE_DATA_SIZE):
#  # Generate those with 0, 1, 2, ..., THRESHOLD_SEQUENCE
#  for j in range(THRESHOLD_SEQUENCE, 0, -1):
#    gen_data_type_1(seq_count=j, min_number=10**(NUMBER_SIZE-1)
#    print("%d, %d, " % (i, j))

# 2. Sequence < X, gap < Y, decision: false
# for i in range(DATE_TYPE_DATA_SIZE):
#  # print("%d" % i)

# 3. Sequence > X, gap > Y, decision: false
# for i in range(DATE_TYPE_DATA_SIZE):
#  # print("%d" % i)

# 4. Sequence > X, gap < Y, decision: false
# for i in range(DATA_SIZE - (DATA_TYPE_SIZE-1) * DATE_TYPE_DATA_SIZE):
#  # print("%d" % i)
