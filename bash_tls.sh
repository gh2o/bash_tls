#!/bin/bash

# Dependencies
# - bash 4.3+
# - bc (for RSA calculations)
# - sha256sum (for pseudorandom function)

set -eu
set -o pipefail
set -o errtrace
trap 'die "command error"' ERR

if [ "$BASH_VERSION" '<' '4.3' ] || (( 64 << 30 < 64 )); then
    echo "Only bash 4.3+ with 64-bit integers is supported." >&2
    exit 1
fi

########################################
## Utilities
########################################

die() {
    local msg="$1"
    echo "FATAL ERROR: $msg">&2

    local i=0 info
    while info=$(caller $i); do
        set -- $info
        local line=$1 func=$2 file=$3
        printf '\t%s at %s:%s\n' "$func" "$file" "$line" >&2
        (( i += 1 ))
    done

    kill -ABRT -$$
}

hex_iter() {
    local str=$1
    local i=0 j=${#str}
    while (( i < j )); do
        echo ${str:i:2}
        (( i += 2 ))
    done
}

hex_len() {
    local str=${1}
    echo $((${#str} / 2))
}

hex_slice_lenient() {
    local str=$1 off=$2 len=${3:-all}
    if [ "$len" = "all" ]; then
        echo ${str:off * 2}
    else
        echo ${str:off * 2:len * 2}
    fi
}

hex_slice() {
    local str=$1 off=$2 len=${3:-all}
    if (( off * 2 > ${#str} )); then
        die 'bad slice'
    fi
    if [ "$len" = "all" ]; then
        echo ${str:off * 2}
    else
        if (( (off + len) * 2 > ${#str} )); then
            die 'bad slice'
        fi
        echo ${str:off * 2:len * 2}
    fi
}

hex_consume() {
    local -n _hs_consume_out=$1 _hs_consume_src=$2
    local i=$3
    if (( ${#_hs_consume_src} < i * 2 )); then
        die 'too little data to consume'
    fi
    _hs_consume_out=${_hs_consume_src:0:i * 2}
    _hs_consume_src=${_hs_consume_src:i * 2}
}

hex_pop() {
    local -n _hs_pop_out=$1 _hs_pop_src=$2
    local i=$3
    local j=$((${#_hs_pop_src} - i * 2))
    if (( j < 0 )); then
        die 'too little data to pop'
    fi
    _hs_pop_out=${_hs_pop_src:j}
    _hs_pop_src=${_hs_pop_src:0:j}
}

hex_int() {
    local hex=$1
    echo $((0x$hex))
}

hex_strip_leading_zeroes() {
    local hex=$1
    while [ "${hex:0:2}" == 00 ]; do hex=${hex:2}; done
    echo "$hex"
}

hex_convert_from_string() {
    local str=$1 out=
    local i=0
    while (( i < ${#str} )); do
        out+=$(printf %02X "'${str:i:1}")
        (( i += 1 ))
    done
    echo $out
}

write_to_fd() {
    local fd=$1 str=$2
    local LC_ALL=C
    local hc hd
    for hc in $(hex_iter $str); do hd+="\x$hc"; done
    echo -ne "$hd" >&${fd}
}

read_from_fd() {
    local fd=$1 size=$2
    local LC_ALL=C
    local i c
    for i in $(eval echo {1..$size}); do
        IFS= read -n 1 -d '' -u $fd -r c || die 'socket closed'
        printf '%02X' "'$c"
    done
}

sha256_digest() {
    local data=$1
    local COPROC digest
    if command -v sha256sum >&${devnullfd}; then
        coproc sha256sum
    elif command -v shasum >&${devnullfd}; then
        coproc shasum -a256
    else
        die 'neither sha256sum nor shasum could be found'
    fi
    local outfd=${COPROC[0]} infd=${COPROC[1]}
    write_to_fd $infd $data
    exec {infd}>&-
    read -d ' ' -u $outfd digest
    exec {outfd}<&-
    echo ${digest^^}
}

########################################
## GF2 arithmetic
########################################

gf2_simplify() {
    # chop off leading zeros
    local -n _gf2_simp_x=$1
    while (( ${#_gf2_simp_x[@]} && _gf2_simp_x[-1] == 0 )); do
        unset '_gf2_simp_x[-1]'
    done
}

gf2_chkbit() {
    local -n _gf2_chkbit_x=$1
    local bit_number=$2
    local i=${_gf2_chkbit_x[bit_number / 32]:-0}
    return $((!(i & 1 << (bit_number % 32))))   # sh return codes are inverted
}

gf2_add() { # xor in GF2
    local -n _gf2_add_dst=$1
    local -n _gf2_add_src=$2
    local should_simplify=${3:-1}
    local i=0
    while (( i < ${#_gf2_add_src[@]} )); do
        local ai=${_gf2_add_dst[i]:-0} bi=${_gf2_add_src[i]}
        _gf2_add_dst[i]=$((ai ^ bi))
        (( i += 1 ))
    done
    if (( should_simplify )); then
        gf2_simplify _gf2_add_dst
    fi
}

gf2_mulx() {
    local -n _gf2_mulx_dst=$1
    local -n _gf2_mulx_mod=$2
    local i=0 si=${_gf2_mulx_dst[0]:-0}
    while (( i < ${#_gf2_mulx_dst[@]} )); do
        local ai=${_gf2_mulx_dst[i]} bi=${_gf2_mulx_dst[i+1]:-0}
        _gf2_mulx_dst[i]=$(((bi << 31 | ai >> 1) & 0xFFFFFFFF))
        (( i += 1 ))
    done
    if (( si & 0x1 )); then
        gf2_add _gf2_mulx_dst _gf2_mulx_mod
    else
        gf2_simplify _gf2_mulx_dst
    fi
}

gf2_lshift() {
    local -n _gf2_val=$1
    local shift_amt=$2
    while (( shift_amt >= 32 )); do
        _gf2_val=(0 ${_gf2_val[@]})
        (( shift_amt -= 32 )) || true
    done
    if (( shift_amt )); then
        local i=${#_gf2_val[@]}
        while (( i >= 0 )); do
            local ai=${_gf2_val[i]:-0}
            if (( i > 0 )); then
                local bi=${_gf2_val[i-1]}
            else
                local bi=0
            fi
            local ci=$(((ai << shift_amt | bi >> (32 - shift_amt)) & 0xFFFFFFFF))
            if (( ci || i < ${#_gf2_val[@]} )); then
                _gf2_val[i]=$ci
            fi
            (( i -= 1 )) || true
        done
    fi
}

gf2_rshift() {
    local -n _gf2_val=$1
    local shift_amt=$2
    while (( shift_amt >= 32 )); do
        unset '_gf2_val[0]'
        (( shift_amt -= 32 )) || true
    done
    if (( shift_amt )); then
        local i=0
        while (( i < ${#_gf2_val[@]} )); do
            local ai=${_gf2_val[i]} bi=${_gf2_val[i+1]:-0}
            _gf2_val[i]=$(((bi << (32 - shift_amt) | ai >> shift_amt) & 0xFFFFFFFF))
            (( i += 1 ))
        done
        gf2_simplify _gf2_val
    fi
}

gf2_dump_to_stderr() {
    local -n _gf2_dump_val=$1
    local i out=
    for i in $(eval echo {0..$((${#_gf2_dump_val[@]}-1))}); do
        out="$(printf %08X ${_gf2_dump_val[i]})${out}"
    done
    echo $out >&2
}

gf2_from_hex() {
    local hex=$1
    local out=
    while [ -n "$hex" ]; do
        local msb=${hex:0:8}
        hex=${hex:8}
        out="$((0x$msb)) $out"
    done
    echo $out
}

gf2_to_hex() {
    local -n _gf2_th_val=$1
    local i out=
    for i in $(eval echo {0..$((${#_gf2_th_val[@]}-1))}); do
        out="$(printf %08X ${_gf2_th_val[i]})${out}"
    done
    echo "$out"
}

########################################
## ASN.1
########################################

asn1_get_off_len() {
    local node=$1
    local header=$(hex_int $(hex_slice "$node" 0 1))
    if (( (header & 0x1F) == 0x1F )); then
        die 'unsupported asn.1 tag'
    fi
    local offset=2
    local length=$(hex_int $(hex_slice "$node" 1 1))
    if (( length & 0x80 )); then
        (( length &= 0x7F, offset += length ))
        length=$(hex_int $(hex_slice "$node" 2 $length))
    fi
    echo $offset $length
}

asn1_enter() {
    local node=$1
    set -- $(asn1_get_off_len "$node")
    local offset=$1 length=$2
    hex_slice "$node" $offset $length
}

asn1_skip() {
    local node=$1
    set -- $(asn1_get_off_len "$node")
    local offset=$1 length=$2
    hex_slice "$node" $((offset + length))
}

########################################
## AES
########################################

AES_S_BOX=(99 124 119 123 242 107 111 197 48 1 103 43 254 215 171 118 202 130 201 125 250 89 71 240 173 212 162 175 156 164 114 192 183 253 147 38 54 63 247 204 52 165 229 241 113 216 49 21 4 199 35 195 24 150 5 154 7 18 128 226 235 39 178 117 9 131 44 26 27 110 90 160 82 59 214 179 41 227 47 132 83 209 0 237 32 252 177 91 106 203 190 57 74 76 88 207 208 239 170 251 67 77 51 133 69 249 2 127 80 60 159 168 81 163 64 143 146 157 56 245 188 182 218 33 16 255 243 210 205 12 19 236 95 151 68 23 196 167 126 61 100 93 25 115 96 129 79 220 34 42 144 136 70 238 184 20 222 94 11 219 224 50 58 10 73 6 36 92 194 211 172 98 145 149 228 121 231 200 55 109 141 213 78 169 108 86 244 234 101 122 174 8 186 120 37 46 28 166 180 198 232 221 116 31 75 189 139 138 112 62 181 102 72 3 246 14 97 53 87 185 134 193 29 158 225 248 152 17 105 217 142 148 155 30 135 233 206 85 40 223 140 161 137 13 191 230 66 104 65 153 45 15 176 84 187 22)
AES_A_MIX=(0 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40 42 44 46 48 50 52 54 56 58 60 62 64 66 68 70 72 74 76 78 80 82 84 86 88 90 92 94 96 98 100 102 104 106 108 110 112 114 116 118 120 122 124 126 128 130 132 134 136 138 140 142 144 146 148 150 152 154 156 158 160 162 164 166 168 170 172 174 176 178 180 182 184 186 188 190 192 194 196 198 200 202 204 206 208 210 212 214 216 218 220 222 224 226 228 230 232 234 236 238 240 242 244 246 248 250 252 254 27 25 31 29 19 17 23 21 11 9 15 13 3 1 7 5 59 57 63 61 51 49 55 53 43 41 47 45 35 33 39 37 91 89 95 93 83 81 87 85 75 73 79 77 67 65 71 69 123 121 127 125 115 113 119 117 107 105 111 109 99 97 103 101 155 153 159 157 147 145 151 149 139 137 143 141 131 129 135 133 187 185 191 189 179 177 183 181 171 169 175 173 163 161 167 165 219 217 223 221 211 209 215 213 203 201 207 205 195 193 199 197 251 249 255 253 243 241 247 245 235 233 239 237 227 225 231 229)
AES_B_MIX=(0 3 6 5 12 15 10 9 24 27 30 29 20 23 18 17 48 51 54 53 60 63 58 57 40 43 46 45 36 39 34 33 96 99 102 101 108 111 106 105 120 123 126 125 116 119 114 113 80 83 86 85 92 95 90 89 72 75 78 77 68 71 66 65 192 195 198 197 204 207 202 201 216 219 222 221 212 215 210 209 240 243 246 245 252 255 250 249 232 235 238 237 228 231 226 225 160 163 166 165 172 175 170 169 184 187 190 189 180 183 178 177 144 147 150 149 156 159 154 153 136 139 142 141 132 135 130 129 155 152 157 158 151 148 145 146 131 128 133 134 143 140 137 138 171 168 173 174 167 164 161 162 179 176 181 182 191 188 185 186 251 248 253 254 247 244 241 242 227 224 229 230 239 236 233 234 203 200 205 206 199 196 193 194 211 208 213 214 223 220 217 218 91 88 93 94 87 84 81 82 67 64 69 70 79 76 73 74 107 104 109 110 103 100 97 98 115 112 117 118 127 124 121 122 59 56 61 62 55 52 49 50 35 32 37 38 47 44 41 42 11 8 13 14 7 4 1 2 19 16 21 22 31 28 25 26)

aes_break_word() {
    local -n _out=$1
    local word=$2
    _out=($((word >> 24 & 0xFF)) $((word >> 16 & 0xFF)) $((word >> 8 & 0xFF)) $((word & 0xFF)))
}

aes_sub_word() {
    local -n _word=$1
    local -n box=${2:-AES_S_BOX}
    local x
    aes_break_word x $_word
    _word=$((box[x[0]] << 24 | box[x[1]] << 16 | box[x[2]] << 8 | box[x[3]]))
}

aes_init_state() {
    local self=$1
    local key=$2

    local Nk=$(($(hex_len $key) / 4))
    local Nr=$((Nk + 6))
    local rcon=1

    local -n self_w=${self}_w
    self_w=()
    local -n self_Nr=${self}_Nr
    self_Nr=$Nr

    while [ -n "$key" ]; do
        local chunk
        hex_consume chunk key 4
        self_w+=($(hex_int $chunk))
    done

    while (( (i=${#self_w[@]}) < 4 * (Nr + 1) )); do
        local temp=${self_w[-1]}
        if (( i % Nk == 0 )); then
            temp=$(((temp << 8 | temp >> 24) & 0xFFFFFFFF))
            aes_sub_word temp
            temp=$((temp ^ (rcon << 24)))
            rcon=$(((rcon << 1) ^ (0x11B & -(rcon >> 7))))
        elif (( Nk > 6 && i % Nk == 4 )); then
            aes_sub_word temp
        fi
        self_w+=($((self_w[-Nk] ^ temp)))
    done
}

aes_do_encrypt() {
    local self=$1
    local block=$2

    local -n self_Nr=${self}_Nr

    local i=0
    local state=($(hex_int $(hex_slice $block  0 4))
                 $(hex_int $(hex_slice $block  4 4))
                 $(hex_int $(hex_slice $block  8 4))
                 $(hex_int $(hex_slice $block 12 4)))

    aes_step_add_round_key state $self 0
    while ((i++ < self_Nr)); do
        aes_step_sub_bytes state
        aes_step_shift_rows state
        ((i < self_Nr)) && aes_step_mix_columns state
        aes_step_add_round_key state $self $i
    done
    printf '%08X%08X%08X%08X\n' ${state[0]} ${state[1]} ${state[2]} ${state[3]}
}

aes_step_add_round_key() {
    local -n _aes_state=$1
    local self=$2
    local round=$3

    local -n self_w=${self}_w

    ((
        _aes_state[0] ^= self_w[4*round+0],
        _aes_state[1] ^= self_w[4*round+1],
        _aes_state[2] ^= self_w[4*round+2],
        _aes_state[3] ^= self_w[4*round+3],
        1
    ))

}

aes_step_sub_bytes() {
    local -n _aes_state=$1
    aes_sub_word '_aes_state[0]'
    aes_sub_word '_aes_state[1]'
    aes_sub_word '_aes_state[2]'
    aes_sub_word '_aes_state[3]'
}

aes_step_shift_rows() {
    local -n _aes_state=$1
    local s_0 s_1 s_2 s_3
    aes_break_word s_0 ${_aes_state[0]}
    aes_break_word s_1 ${_aes_state[1]}
    aes_break_word s_2 ${_aes_state[2]}
    aes_break_word s_3 ${_aes_state[3]}

    ((
        _aes_state[0] = s_0[0] << 24 | s_1[1] << 16 | s_2[2] << 8 | s_3[3],
        _aes_state[1] = s_1[0] << 24 | s_2[1] << 16 | s_3[2] << 8 | s_0[3],
        _aes_state[2] = s_2[0] << 24 | s_3[1] << 16 | s_0[2] << 8 | s_1[3],
        _aes_state[3] = s_3[0] << 24 | s_0[1] << 16 | s_1[2] << 8 | s_2[3],
        1
    ))
}

aes_step_mix_columns() {
    local -n _aes_state=$1
    local i
    for i in 0 1 2 3; do
        local w=${_aes_state[i]}
        local x; aes_break_word x $w
        local a=($((AES_A_MIX[x[0]])) $((AES_A_MIX[x[1]])) $((AES_A_MIX[x[2]])) $((AES_A_MIX[x[3]])))
        local b=($((AES_B_MIX[x[0]])) $((AES_B_MIX[x[1]])) $((AES_B_MIX[x[2]])) $((AES_B_MIX[x[3]])))
        _aes_state[$i]=$(((a[0] ^ b[1] ^ x[2] ^ x[3]) << 24 |
                          (a[1] ^ b[2] ^ x[3] ^ x[0]) << 16 |
                          (a[2] ^ b[3] ^ x[0] ^ x[1]) <<  8 |
                          (a[3] ^ b[0] ^ x[1] ^ x[2])))
    done
}

########################################
## GCM
########################################

AES_GCM_MULX_MOD=(0 0 0 3774873600)
AES_GCM_REDUCTION_TABLE=(0 450 900 582 1800 1738 1164 1358 3600 4050 3476 3158 2328 2266 2716 2910 7200 7650 8100 7782 6952 6890 6316 6510 4656 5106 4532 4214 5432 5370 5820 6014 14400 14722 15300 14854 16200 16010 15564 15630 13904 14226 13780 13334 12632 12442 13020 13086 9312 9634 10212 9766 9064 8874 8428 8494 10864 11186 10740 10294 11640 11450 12028 12094 28800 28994 29444 29382 30600 30282 29708 30158 32400 32594 32020 31958 31128 30810 31260 31710 27808 28002 28452 28390 27560 27242 26668 27118 25264 25458 24884 24822 26040 25722 26172 26622 18624 18690 19268 19078 20424 19978 19532 19854 18128 18194 17748 17558 16856 16410 16988 17310 21728 21794 22372 22182 21480 21034 20588 20910 23280 23346 22900 22710 24056 23610 24188 24510 57600 57538 57988 58182 58888 59338 58764 58446 61200 61138 60564 60758 59416 59866 60316 59998 64800 64738 65188 65382 64040 64490 63916 63598 62256 62194 61620 61814 62520 62970 63420 63102 55616 55426 56004 56070 56904 57226 56780 56334 55120 54930 54484 54550 53336 53658 54236 53790 50528 50338 50916 50982 49768 50090 49644 49198 52080 51890 51444 51510 52344 52666 53244 52798 37248 36930 37380 37830 38536 38730 38156 38094 40848 40530 39956 40406 39064 39258 39708 39646 36256 35938 36388 36838 35496 35690 35116 35054 33712 33394 32820 33270 33976 34170 34620 34558 43456 43010 43588 43910 44744 44810 44364 44174 42960 42514 42068 42390 41176 41242 41820 41630 46560 46114 46692 47014 45800 45866 45420 45230 48112 47666 47220 47542 48376 48442 49020 48830)

aes_gcm_init_state() {
    local self=$1
    local key=$2
    local iv=$3

    local -n self_iv=${self}_iv
    self_iv=$iv

    aes_init_state ${self}_aes $key

    # generate multiplication table
    local agis_m_hex=$(aes_do_encrypt ${self}_aes 00000000000000000000000000000000)
    local agis_m=($(gf2_from_hex $agis_m_hex))

    local i s
    for i in {0..255}; do
        local -n mult_table_entry=${self}_mt${i}
        mult_table_entry=()
    done
    for s in {7..0}; do
        for i in {0..255}; do
            if (( i & (1 << s) )); then
                local -n mult_table_entry=${self}_mt${i}
                gf2_add mult_table_entry agis_m
            fi
        done
        gf2_mulx agis_m AES_GCM_MULX_MOD
    done
}

aes_gcm_do_encrypt() {
    local self=$1 nonce=$2 header=$3 fragment=$4
    local -n self_iv=${self}_iv
    set -- $(aes_gcm_inner_crypt ${self} ${self_iv}${nonce} "${header}" "${fragment}" 0)
    local IFS=
    echo "$*"
}

aes_gcm_do_decrypt() {
    local self=$1 nonce=$2 header=$3 fragment=$4
    local -n self_iv=${self}_iv
    local given_tag
    hex_pop given_tag fragment 16
    set -- $(aes_gcm_inner_crypt ${self} ${self_iv}${nonce} "${header}" "${fragment}" 1)
    if (( $# == 2 )); then
        local fragment=$1 expected_tag=$2
    else
        local fragment= expected_tag=$1
    fi
    [ $given_tag == $expected_tag ] || die 'bad tag'
    echo "$fragment"
}

aes_gcm_inner_crypt() {
    local self=$1 iv=$2 addl=$3 data=$4 decrypt=$5
    local agic_hash_state=() newdata=
    local Ji=1

    local i=0 aj=$(hex_len "$addl")
    while (( i < aj )); do
        aes_gcm_hash_block agic_hash_state $(hex_slice_lenient $addl $i 16)
        (( i += 16 ))
    done

    local i=0 dj=$(hex_len "$data")
    while (( i < dj )); do
        (( Ji += 1 ))
        printf "[%4u/%4u]" $((i/16)) $(((dj+15)/16)) >&2
        local chunk=$(hex_slice_lenient "$data" $i 16) newchunk=
        local smudge=$(aes_do_encrypt ${self}_aes ${iv}$(printf %08X $Ji))
        if (( decrypt )); then
            aes_gcm_hash_block agic_hash_state ${chunk}
        fi
        while [ -n "$chunk" ]; do
            local chunk_byte smudge_byte newchunk_append
            hex_consume chunk_byte chunk 1
            hex_consume smudge_byte smudge 1
            printf -v newchunk_append %02X $((0x$chunk_byte ^ 0x$smudge_byte))
            newchunk+=${newchunk_append}
        done
        if ! (( decrypt )); then
            aes_gcm_hash_block agic_hash_state ${newchunk}
        fi
        newdata+=$newchunk
        printf $'\b\b\b\b\b\b\b\b\b\b\b' >&2
        (( i += 16 ))
    done

    aes_gcm_hash_block agic_hash_state $(printf %016X $((aj * 8)))$(printf %016X $((dj * 8)))

    local tag_smudge=($(gf2_from_hex $(aes_do_encrypt ${self}_aes ${iv}00000001)))
    gf2_add agic_hash_state tag_smudge
    echo ${newdata} $(gf2_to_hex agic_hash_state)
}

aes_gcm_hash_block() {
    local -n aghb_state=$1
    local hex_chunk=$2
    local hex_chunk_len=$(hex_len "$hex_chunk")

    # pad to 16 bytes
    while (( hex_chunk_len < 16 )); do
        hex_chunk+=00
        (( hex_chunk_len += 1 ))
    done

    local aghb_old_state=(${aghb_state[@]})
    aghb_state=()

    local i
    for i in {0..15}; do
        local hex_byte
        hex_pop hex_byte hex_chunk 1
        local aghb_low=${aghb_old_state[0]:-0}
        local -n mult_table_entry=${self}_mt$((0x$hex_byte ^ (aghb_low & 0xFF)))
        local mt_const=(${mult_table_entry[@]})     # copy mult_table_entry
        gf2_lshift mt_const $((8 * i))
        gf2_add    aghb_state mt_const
        gf2_rshift aghb_old_state 8
    done

    for i in {1..15}; do
        local aghb_low=${aghb_state[0]:-0}
        local red_val=${AES_GCM_REDUCTION_TABLE[aghb_low & 0xFF]}
        local red_int=(0 0 0 $((red_val << 16)))
        gf2_rshift aghb_state 8
        gf2_add    aghb_state red_int
    done
}

########################################
## HMAC+PRF
########################################

hmac_sha256_digest() {
    local key=$1 msg=$2
    if (( $(hex_len "$key") > 64 )); then
        key=$((sha256_digest "$key"))
    fi
    while (( $(hex_len "$key") < 64 )); do
        key+=00
    done
    local ikey=($(gf2_from_hex $key))
    local ipad=()
    while (( ${#ipad[@]} < 16 )); do ipad+=(0x36363636); done
    gf2_add ikey ipad 0
    local okey=($(gf2_from_hex $key))
    local opad=()
    while (( ${#opad[@]} < 16 )); do opad+=(0x5C5C5C5C); done
    gf2_add okey opad 0

    local inner_digest=$(sha256_digest $(gf2_to_hex ikey)${msg})
    local outer_digest=$(sha256_digest $(gf2_to_hex okey)${inner_digest})
    echo "$outer_digest"
}

hmac_sha256_prf() {
    local secret=$1 label=$2 seed=$3 length=$4
    label=$(hex_convert_from_string "$label")
    seed=${label}${seed}
    local A=${seed}
    local result=
    while (( $(hex_len "$result") < length )); do
        A=$(hmac_sha256_digest "$secret" "${A}")
        result+=$(hmac_sha256_digest "$secret" "${A}${seed}")
    done
    hex_slice "$result" 0 $length
}

########################################
## TLS
########################################

TLS_RECORD_MAX_SIZE=16384
RSA_BC_POW_PRGM='r=1;while(e){if(e%2)r=(r*b)%m;b=(b*b)%m;e/=2};r'

tls_all_handshakes=
tls_handshake_buffer=
tls_changecipherspec_buffer=
tls_appdata_buffer=

tls_write_gcm=
tls_write_encrypted=0
tls_write_seq=0

tls_read_gcm=
tls_read_encrypted=0
tls_read_seq=0

tls_send_record() {
    local type=$1 fragment=$2
    local i=0 j=$(hex_len "$fragment")
    while (( i < j )); do
        local chunk=$(hex_slice_lenient "$fragment" $i $TLS_RECORD_MAX_SIZE)
        if (( $tls_write_encrypted )); then
            local nonce=$(printf %016X $tls_write_seq)
            local header=${nonce}${type}0303$(printf %04X $(hex_len $chunk))
            chunk=${nonce}$(aes_gcm_do_encrypt tls_write_gcm $nonce $header $chunk)
            (( tls_write_seq += 1 ))
        fi
        write_to_fd $sockfd ${type}0303$(printf %04X $(hex_len $chunk))${chunk}
        (( i += TLS_RECORD_MAX_SIZE ))
    done
}

tls_process_record() {
    local type version dlen length fragment
    type=$(read_from_fd $sockfd 1)
    version=$(read_from_fd $sockfd 2)
    dlen=$(read_from_fd $sockfd 2)
    length=$(hex_int $dlen)
    fragment=$(read_from_fd $sockfd $length)

    if (( $tls_read_encrypted )); then
        # decrypted length is 24 bytes shorter (8 from nonce, 16 from GCM tag)
        local nonce
        local header=$(printf %016X $tls_read_seq)${type}${version}$(printf %04X $((length - 24)))
        hex_consume nonce fragment 8
        fragment=$(aes_gcm_do_decrypt tls_read_gcm $nonce $header $fragment)
        (( tls_read_seq += 1 ))
    fi

    case $type in
        14) # change cipher spec
            tls_changecipherspec_buffer+=$fragment
            ;;
        15) # alert
            local value=$(hex_int $fragment)
            die "SSL alert level $((value >> 8)) description $((value & 0xFF))"
            ;;
        16) # handshake
            tls_handshake_buffer+=$fragment
            ;;
        17) # application data
            tls_appdata_buffer+=$fragment
            ;;
        *)
            die 'unknown record type'
            ;;
    esac
}

tls_send_handshake() {
    local type=$1 msg=$2
    local fragment=${type}$(printf %06X $(hex_len $msg))${msg}
    tls_all_handshakes+=$fragment
    tls_send_record 16 $fragment
}

tls_recv_handshake() {
    local expected_type=$1
    local -n _tls_rh_msg=$2
    while true; do
        if (( $(hex_len "$tls_handshake_buffer") >= 4 )); then
            local type=$(hex_slice $tls_handshake_buffer 0 1)
            local dlen=$(hex_slice $tls_handshake_buffer 1 3)
            local length=$(hex_int $dlen)
            if [ $type != $expected_type ]; then
                die 'unexpected handshake message'
            fi
            if (( $(hex_len $tls_handshake_buffer) >= 4 + length )); then
                hex_consume _tls_rh_msg tls_handshake_buffer 4
                hex_consume _tls_rh_msg tls_handshake_buffer $length
                tls_all_handshakes+=${type}${dlen}${_tls_rh_msg}
                return
            fi
        fi
        tls_process_record
    done
}

tls_do_handshake() {
    local hostname=$1
    local tmp_dlen

    ##### ClientHello
    local sni_ext=00$(printf %04X ${#hostname})$(hex_convert_from_string "$hostname")
    sni_ext=$(printf %04X $(hex_len $sni_ext))${sni_ext}
    sni_ext=0000$(printf %04X $(hex_len $sni_ext))${sni_ext}
    local all_exts=${sni_ext}
    local cipher_suite=009C
    local client_random=$(read_from_fd $randfd 32)
    local client_hello=0303             # protocol version
    client_hello+=$client_random        # client random
    client_hello+=00                    # session ID
    client_hello+=0002${cipher_suite}   # cipher suite list
    client_hello+=0100                  # compresion methods
    client_hello+=$(printf %04X $(hex_len $all_exts))${all_exts}
    tls_send_handshake 01 $client_hello

    ##### ServerHello
    local server_hello
    tls_recv_handshake 02 server_hello
    local server_random=$(hex_slice "$server_hello" 2 32)

    ##### Certificate
    local certificate
    tls_recv_handshake 0B certificate
    # get certificate set
    hex_consume tmp_dlen certificate 3
    certificate=$(hex_slice "$certificate" 0 $(hex_int $tmp_dlen))
    # get first certificate
    hex_consume tmp_dlen certificate 3
    certificate=$(hex_slice "$certificate" 0 $(hex_int $tmp_dlen))

    ##### ServerHelloDone
    local server_hello_done
    tls_recv_handshake 0E server_hello_done

    ##### extract public key from certificate
    local pk_m pk_e
    certificate=$(asn1_enter "$certificate")
    certificate=$(asn1_enter "$certificate")
    if (( $(hex_int $(hex_slice "$certificate" 0 1)) & 0xC0 )); then
        # skip version tag
        certificate=$(asn1_skip "$certificate")
    fi
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_enter "$certificate")
    local algo=$(asn1_enter "$certificate")
    algo=$(asn1_enter "$algo")
    if [ "$algo" != 2A864886F70D010101 ]; then
        die 'not RSA certificate'
    fi
    certificate=$(asn1_skip "$certificate")
    certificate=$(asn1_enter "$certificate")
    if [ $(hex_slice "$certificate" 0 1) != 00 ]; then
        die 'bad key padding'
    fi
    certificate=$(hex_slice "$certificate" 1)
    certificate=$(asn1_enter "$certificate")
    pk_m=$(hex_strip_leading_zeroes $(asn1_enter "$certificate"))
    certificate=$(asn1_skip "$certificate")
    pk_e=$(hex_strip_leading_zeroes $(asn1_enter "$certificate"))
    if [ -z "$pk_m" ] || [ -z "$pk_e" ]; then
        die 'empty public key'
    fi

    ##### generate premaster secret
    local pre_master_secret=0303$(read_from_fd $randfd 46)

    ##### encrypt premaster secret
    local padded_pms=00${pre_master_secret}
    while (( $(hex_len $padded_pms) < $(hex_len $pk_m) - 2 )); do
        padded_pms=AA${padded_pms}
    done
    padded_pms=0002${padded_pms}
    local encr_pms=$(BC_LINE_LENGTH=9999 bc \
        <<<"obase=16;ibase=16;b=${padded_pms};e=${pk_e};m=${pk_m};${RSA_BC_POW_PRGM}")
    while (( ${#encr_pms} < ${#pk_m} )); do encr_pms=0${encr_pms}; done

    # ClientKeyExchange
    local client_kex=$(printf %04X $(hex_len $encr_pms))${encr_pms}
    tls_send_handshake 10 $client_kex

    ##### calculate master secret
    local master_secret=$(hmac_sha256_prf $pre_master_secret 'master secret' \
        ${client_random}${server_random} 48)
    local key_block=$(hmac_sha256_prf $master_secret 'key expansion' \
        ${server_random}${client_random} 40)

    # Client ChangeCipherSpec
    tls_send_record 14 01
    aes_gcm_init_state tls_write_gcm $(hex_slice $key_block 0 16) $(hex_slice $key_block 32 4)
    tls_write_encrypted=1

    # Client Finished
    local verify_data=$(hmac_sha256_prf $master_secret 'client finished' \
        $(sha256_digest $tls_all_handshakes) 12)
    tls_send_handshake 14 $verify_data

    # Server ChangeCipherSpec
    while [ -z "$tls_changecipherspec_buffer" ]; do
        tls_process_record
    done
    if [ "$tls_changecipherspec_buffer" != 01 ]; then
        die 'bad CCS msg'
    fi
    aes_gcm_init_state tls_read_gcm $(hex_slice $key_block 16 16) $(hex_slice $key_block 36 4)
    tls_read_encrypted=1

    # Server Finished
    local verify_data=$(hmac_sha256_prf $master_secret 'server finished' \
        $(sha256_digest $tls_all_handshakes) 12)
    local server_finished
    tls_recv_handshake 14 server_finished
    if [ "$server_finished" != "$verify_data" ]; then
        die 'bad handshake hash'
    fi
}

tls_send_data() {
    local data=$1
    tls_send_record 17 $1
}

tls_recv_data() {
    local -n _tls_recv_data_buf=$1
    while [ -z "$tls_appdata_buffer" ]; do
        tls_process_record
    done
    _tls_recv_data_buf=$tls_appdata_buffer
    tls_appdata_buffer=
}

main() {
    if [ -n "${1:-}" ]; then
        local url=$1
    else
        local url=https://www.google.com/robots.txt
    fi
    url=${url#https://}
    hostname=${url%%/*}
    path=/${url#*/}
    if [ "$hostname" = "$path" ]; then path=/; fi

    exec {sockfd}<>/dev/tcp/"$hostname"/443
    exec {randfd}</dev/urandom
    exec {devnullfd}>/dev/null

    local get_req="GET ${path} HTTP/1.1"$'\r\n'
    get_req+="Host: ${hostname}"$'\r\n'
    get_req+="Connection: close"$'\r\n\r\n'

    echo 'running handshake ...' >&2
    tls_do_handshake "$hostname"
    echo 'sending request ...' >&2
    tls_send_data $(hex_convert_from_string "$get_req")
    echo 'receiving response ...' >&2
    while true; do
        local data
        tls_recv_data data
        write_to_fd 1 $data
    done
}

main "$@"
