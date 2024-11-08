import argparse 
import csv 



def count(filename): 
    lengths = {}
    with open(filename) as f:
        r = csv.reader(f)
        i = 0 
        ref_len = 4001
        for row in r: 
            # print(row)
            # raise SystemExit
            if len(row) not in lengths: 
                lengths[len(row)] = 1
            else: 
                lengths[len(row)] += 1
            
            # if len(row) != ref_len:
            #     print(f"line nb {i}: {row[0]}")
            #     # raise SystemExit
            # elif i != 0: 
            #     print("----")
            #     print("ok")
            #     print(f"line nb {i}: {row[0]}")
            #     print("-----")
            # if i == 100: 
            #     raise SystemExit
            i+= 1
    print(lengths)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Just count csv")
    parser.add_argument('--input_csv', '-i', help='CSV file', required=True)

    args = parser.parse_args()

    count(args.input_csv)