package util

func PKCS7Padding(data *[]byte, blockSize int) {
	padNum := blockSize - (len(*data) % blockSize)

	if padNum == 0 { // 如果长度刚刚好，则padding一整个block
		padNum = blockSize
	}

	for i := 0; i < padNum; i++ {
		*data = append(*data, byte(padNum))
	}
}

func PKCS7UnPadding(data *[]byte) {
	padNum := (*data)[len(*data)-1]
	*data = (*data)[0:len(*data)-int(padNum)]
}