package aes

import (
    "fmt"
)

const Nb int = 4

var (
	Nr int 
	Nb_k int 
    Roundkey [240]byte 
    Key      [32]byte
    state    [4][4]byte
    in       [16]byte
    out      [16]byte
)

var Sbox = [256]byte{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, //F
}

var Rcon = [11]byte{
//   0     1     2     3      4    5     6     7     8    9     10
    0x87, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};


func KeyExpansion() {
    var tempByte [4]byte
    var a0       byte 

    for i := 0; i < Nb_k; i++ {
        Roundkey[i * 4] = Key[i * 4]
        Roundkey[i *4 + 1] = Key[i * 4 + 1]
        Roundkey[i *4 + 2] = Key[i * 4 + 2]
        Roundkey[i *4 + 3] = Key[i * 4 + 3]
    }

    for i := Nb_k; i < (Nb * (Nr + 1)); i++ {
        for j := 0; j < 4; j++ { // 處理每個block(W)
            tempByte[j] = Roundkey[(i - 1) * 4 + j]; // 要新增一個block(Word)故取前一個的W值存入tempW
        }
        if i % Nb_k == 0 {
            /**
             * Ex: AES-128 when generate W4, will use W3 do SubWord(RotWord(tempW)) XOR Rcon[4/4]
             *     AES-128 i 是 4 的倍數的 Wi 用 Wi-1產生 Wi =  SubWord(RotWord(Wi-1)) XOR Rcon[i/4]
             */

            // RotWord function, [a0, a1, a2, a3](4byte) left circular shift in a word [a1, a2, a3, a0]
            a0 = tempByte[0]
            tempByte[0] = tempByte[1]
            tempByte[1] = tempByte[2]
            tempByte[2] = tempByte[3]
            tempByte[3] = a0

            // SubWord function (S-Box substitution)
            tempByte[0] = Sbox[int(tempByte[0])]
            tempByte[1] = Sbox[int(tempByte[1])]
            tempByte[2] = Sbox[int(tempByte[2])]
            tempByte[3] = Sbox[int(tempByte[3])]
            
            // XOR Rcon[i/4], only leftmost byte are changed (只會XOR最左的byte)
            tempByte[0] = tempByte[0] ^ Rcon[i / Nb_k]
        } else if (Nb_k == 8 && i % Nb_k == 4){
            // Only AES-256 used, 僅 AES-256 使用此規則, 
            // 當 i mod 4 = 0 且 i mod 8 ≠ 0 時，Wn = SubWord (Wn−1) XOR Wn−8
            tempByte[0] = Sbox[int(tempByte[0])]
            tempByte[1] = Sbox[int(tempByte[1])]
            tempByte[2] = Sbox[int(tempByte[2])]
            tempByte[3] = Sbox[int(tempByte[3])]
        }
        /**
         * Wn = Wn-1 XOR Wk    k = current word - Nb_k
         * Ex: AES-128   Nb_k = 4  when W5 = Wn-1(W4) XOR Wk(W1)
         * Ex: AES-256   Nb_k = 8  when W10 = Wn-1(W9) XOR Wk(W2) 
         */
        Roundkey[i * 4 + 0] = Roundkey[(i - Nb_k) * 4 + 0] ^ tempByte[0]
        Roundkey[i * 4 + 1] = Roundkey[(i - Nb_k) * 4 + 1] ^ tempByte[1]
        Roundkey[i * 4 + 2] = Roundkey[(i - Nb_k) * 4 + 2] ^ tempByte[2]
        Roundkey[i * 4 + 3] = Roundkey[(i - Nb_k) * 4 + 3] ^ tempByte[3]
    }
}

func AddRoundKey(round int) {
    /**
     * 根據round來使用key(每次用1個block = 16byte)
     * first key index = round * 16 bytes = round * Nb * 4;
     * Nb = 4
     */
    for i := 0; i < 4; i++ {
        for j := 0; j < 4; j++ {
            state[j][i] ^= Roundkey[(i * Nb + j) + (round * Nb * 4)]
        }
    }
}


func SubBytes(){
    for i := 0; i < 4; i++ {
        for j := 0; j < 4; j++ {
            state[i][j] = Sbox[state[i][j]]
        }
    }
}

func ShiftRows(){
    var tempByte byte;
    
    // 2nd row left Circular Shift 1 byte
    tempByte    = state[1][0]
    state[1][0] = state[1][1]
    state[1][1] = state[1][2]
    state[1][2] = state[1][3]
    state[1][3] = tempByte

    // 3th row left Circular Shift 2 byte
    tempByte    = state[2][0]
    state[2][0] = state[2][2]
    state[2][2] = tempByte

    tempByte    = state[2][1]
    state[2][1] = state[2][3]
    state[2][3] = tempByte

    // 4th row left Circular Shift 3 byte
    tempByte    = state[3][0]
    state[3][0] = state[3][3]
    state[3][3] = state[3][2]
    state[3][2] = state[3][1]
    state[3][1] = tempByte
}


func xtime(x byte) byte {
    return ((x << 1) ^ (((x >> 7) & 0x01) * 0x1b))
}

func MixColumns() {
    var Tmp, Tm, t byte;
    for i := 0; i < 4; i++ {
        t   = state[0][i]
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]
        Tm  = state[0][i] ^ state[1][i]
        Tm = xtime(Tm)
        state[0][i] ^= Tm ^ Tmp
        Tm  = state[1][i] ^ state[2][i]
        Tm = xtime(Tm)
        state[1][i] ^= Tm ^ Tmp
        Tm  = state[2][i] ^ state[3][i]
        Tm = xtime(Tm)
        state[2][i] ^= Tm ^ Tmp
        Tm  = state[3][i] ^ t
        Tm = xtime(Tm)
        state[3][i] ^= Tm ^ Tmp
    }
}


func Cipher() {
     round := 0
    
    /**
     *  將in[](plaintext) 轉換成 column 排列方式
     *  圖示:
     *  [b0 b1 ... b15] -> [b0 b4 b8  b12
     *                      b1 b5 b9  b13
     *                      b2 b6 b10 b14
     *                      b3 b7 b11 b15]
     */
    for i := 0; i < 4; i++{
        for j := 0; j < 4; j++ {
            state[j][i] = in[i * 4 + j]
        }
    }

    

    // round 0 : add round key, 第0回合: 僅執行-key XOR block - key使用[w0 ~ w3]
    AddRoundKey(0)

    // Round 1 ~ Nr-1, 反覆執行 1 ~ Nr-1回合
    for round = 1; round < Nr; round++{
        SubBytes()
        ShiftRows()
        MixColumns()
        AddRoundKey(round)
    }

    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
    SubBytes()
    ShiftRows()
    AddRoundKey(Nr)

    /**
     *  將state[] transform 到 out[]上
     *  圖示:
     *   [c0 c4 c8  c12
     *    c1 c5 c9  c13    --> [c0 c1 c2 ... c15]
     *    c2 c6 c10 c14
     *    c3 c7 c11 c15]
     */
    for i := 0; i < 4; i++ {
        for j := 0; j < 4; j++ {
            out[i * 4 + j]=state[j][i]
        }
    } 
}

func printUnsignedCharArrayToInt( in [16]byte, size int){
    for  i := 0; i < size; i++ {
        fmt.Printf("%d ", in[i]);
    }
    fmt.Printf("\n")
}


func Encrypto(plaintext []byte, key []byte) []byte {

    ret := make([]byte, 0)

    keySizeInBit := len(key) * 8
    Nb_k = keySizeInBit / 32;     // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr   = Nb_k + 6;         // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
    switch keySizeInBit {
        case 128: {
            for i := 0; i < 16; i++ {
                Key[i] = key[i]
            }
        }
        case 192: {
            for i := 0; i < 24; i++ {
                Key[i] = key[i]
            }
        }
        case 256: {
            for i := 0; i < 32; i++ {
                Key[i] = key[i]
            }
        }
        default: {
            fmt.Printf("key size must be 128, 192 or 256bits\n")
            return nil
        }
    }

    KeyExpansion()

    for i := 0; i < len(plaintext); i += 16 {
        for j := 0; j < 16; j++ {
            in[j] = plaintext[i+j]
        }
        Cipher()
        // printUnsignedCharArrayToInt(out, 16)
        for i := 0; i < 16; i++ {
            ret = append(ret, out[i])
        }
    }
    return ret
}