import pandas as pd
import r2pipe as r2
import concurrent.futures
import threading

BYTE_LENGTH = 2000
DATASET_PATH = "./dataset/malware_original_mips.csv"
DATASET_FOLDER = "/home/mandy900619/data/Malware202403/"
CPU_ARCH = "mips"
# MAX_WORKERS = 10

print(f"Loading {CPU_ARCH} dataset from {DATASET_PATH}...")
dataset = pd.read_csv(DATASET_PATH)

notHaveByteSequence = True

def split_hex_string(hex_string):
    return " ".join([hex_string[i:i+2] for i in range(0, len(hex_string), 2)])

def process_row(row, remaining_files_counter):
    file_path = DATASET_FOLDER + row.file_name[:2] + "/" + row.file_name
    byteAnalysis = r2.open(file_path, flags=["-2"])
    out = byteAnalysis.cmd(f"px* {BYTE_LENGTH}")
    byteAnalysis.cmd("quit")
    lines = out.strip().split("\n")
    byteSeqence = [line[3:-1] for line in lines if not line.startswith("s-")]
    byteSeqence = "".join(byteSeqence)
    byteSeqence = split_hex_string(byteSeqence)

    with remaining_files_counter.get_lock():
        remaining_files_counter.value -= 1
        if remaining_files_counter.value % 10 == 0:
            print(f"Remaining files: {remaining_files_counter.value}", end="\r")

    return row.Index, byteSeqence

if notHaveByteSequence:
    print(f"Extract byte sequences from {CPU_ARCH} dataset...")
    print(f"Extracting byte sequences of length {BYTE_LENGTH}...")

    from multiprocessing import Value

    remaining_files_counter = Value('i', len(dataset))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_row, row, remaining_files_counter) for row in dataset.itertuples()]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    for index, byteSeqence in results:
        dataset.at[index, "byte_sequence"] = byteSeqence

    OUTPUT_PATH = f"./dataset/malware_original_{CPU_ARCH}_byte_sequence{BYTE_LENGTH}_split.csv"
    dataset.to_csv(OUTPUT_PATH, index=False)
