#!/bin/bash

mkdir -p "test-results"

# Generate data once, to speed things up
# Won't make a difference the tests, as long as enough data is generated.
# The tests will fail if not enough data was available
if [ ! -f test.bin ]; then
	./build/linux/release/main | head -c 10000000000 > test.bin
fi

# Tests to run
tests=()

tests+=('diehard_birthdays')
tests+=('diehard_operm5')
tests+=('diehard_rank_32x32')
tests+=('diehard_rank_6x8')
tests+=('diehard_bitstream')
tests+=('diehard_count_1s_str')
tests+=('diehard_count_1s_byt')
tests+=('diehard_parking_lot')
tests+=('diehard_2dsphere')
tests+=('diehard_3dsphere')
tests+=('diehard_squeeze')
tests+=('diehard_runs')
tests+=('diehard_runs')
tests+=('diehard_craps')
tests+=('diehard_craps')
tests+=('marsaglia_tsand_gcd')
tests+=('marsaglia_tsand_gcd')
tests+=('sts_monobit')
tests+=('sts_runs')
tests+=('sts_serial')
tests+=('rgb_bitdist -n 1')
tests+=('rgb_bitdist -n 2')
tests+=('rgb_minimum_distance')
tests+=('rgb_permutations')
tests+=('rgb_lagged_sum')

commands_file=$(mktemp)
dest_file=$(mktemp)

for key in "${tests[@]}"
do
	#echo "${key}" >> $commands_file
	dest=$(echo $key | sed -e 's/[^A-Za-z0-9._-]/_/g')   # >> $dest_file
	#echo $key | sed -e 's/[^A-Za-z0-9._-]/_/g' >> $dest_file
	echo "cat test.bin | dieharder -g 200 -Y 1 -k 2 -m 10 -d ${key} > test-results/${dest}.txt" >> $commands_file
done


echo $commands_file


#parallel -P 2 -v -d \\n --xapply cat test.bin | dieharder -g 200 -Y 1 -k 2 -m 10 -d {1} > test-results/{2}.txt :::: ${commands_file} :::: $dest_file

parallel -P 2 -v sh -c {} :::: ${commands_file}
