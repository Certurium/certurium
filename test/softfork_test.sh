#!/bin/bash

cleanup () {
    agt_cli stop
    rm -rf "$datadir"
}

mine_block () {
    agt_cli generatetoaddress 1 "$1" 1>/dev/null
    (( "timestamp+=10" ))
    agt_cli setmocktime "$timestamp"
}

dummy_mine () {
    mine_block "$other_address" > /dev/null 2>&1
}

agt_cli () {
    src/argentumnt-cli -regtest -datadir="$datadir" "$@"
}

get_status () {
    agt_cli getblockchaininfo | jq .bip9_softforks.coinbase.status
}

get_height () {
   agt_cli getblockchaininfo | jq .blocks
}

start_server () {
    src/argentumntd -daemon -regtest -datadir="$datadir" -txindex -blockversion="$1"
    sleep 3
}

stop_server () {
    agt_cli stop
    sleep 3
}

assert_string_eql () {
    if [ "$1" != "$2" ]; then
        echo "got '$1' expected '$2'"
        exit 1
    fi
}

if ! command -v jq > /dev/null; then
    echo please install jq
    exit 1
fi

trap cleanup EXIT

datadir=$(mktemp -d)

# 0X20000000
bip9_flag_unset=536870912
# 0X20000004 (third bit)
bip9_flag_set=536870916

miner_confirmation_window=144
change_activation_threshold=108

start_server $bip9_flag_set

whitelisted_address='2MsyxuTGH2Yywuh6tV54H6gVWBQwSTfyBU7'
other_address='2NA1keVWTLwCcH2fZXvRKdPYHC5E5dPQHD5'

##### Mine second-to-last block of first confirmation window (genesis counts as well)
timestamp=$(date +%s)
end=$((miner_confirmation_window - 2))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

assert_string_eql '"defined"' "$(get_status)"

##### Mine last block of first confirmation window
mine_block $other_address

assert_string_eql '"started"' "$(get_status)"

##### Mine one block less than necessary
end=$((change_activation_threshold - 1))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

assert_string_eql '"started"' "$(get_status)"

stop_server
start_server $bip9_flag_unset
# for any but the first server startups, the first generatetoaddress
# mine fails ("time-too-old").
# It is likely connected to the hacky use of setmocktime, which is itself
# necessitated by the validation rule that block times must strictly
# monotonically increase.
# We therefore call mine_block once whenever we restart the server.
dummy_mine

end=$((miner_confirmation_window - change_activation_threshold + 1))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

assert_string_eql '"started"' "$(get_status)"

stop_server
start_server $bip9_flag_set
dummy_mine

##### Mine enough blocks to lock in
end=$((change_activation_threshold))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

stop_server
start_server $bip9_flag_unset
dummy_mine

##### Mine all but one of the rest of the blocks of activation window
end=$((miner_confirmation_window - change_activation_threshold - 1))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

assert_string_eql '"started"' "$(get_status)"

mine_block $other_address
assert_string_eql '"locked_in"' "$(get_status)"

##### Mine all but one block of the next retargeting window
end=$((miner_confirmation_window - 1))
for _ in  $(seq 1 $end); do
    mine_block $other_address
done

assert_string_eql '"locked_in"' "$(get_status)"

mine_block $other_address
assert_string_eql '"active"' "$(get_status)"

assert_string_eql '575' "$(get_height)"
mine_block $other_address  > /dev/null 2>&1
assert_string_eql '575' "$(get_height)"

mine_block $whitelisted_address
assert_string_eql '576' "$(get_height)"
