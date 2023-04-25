package util

/**
 * 填充函数，填充方式为PKCS7
 * @param data      欲填充的数据
 * @param blockSize 每个块的大小
 */
func PKCS7Padding(data *[]byte, blockSize int) {
	padNum := blockSize - (len(*data) % blockSize)

	if padNum == 0 { // 如果长度刚刚好，则padding一整个block
		padNum = blockSize
	}

	for i := 0; i < padNum; i++ {
		*data = append(*data, byte(padNum))
	}
}

/**
 * 去填充函数，去填充方式为PKCS7
 * @param data      欲去填充的数据
 */
func PKCS7UnPadding(data *[]byte) {
	padNum := (*data)[len(*data)-1]
	*data = (*data)[0 : len(*data)-int(padNum)]
}
