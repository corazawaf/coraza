package utils

func IsSpace(char byte) bool {
	//https://en.cppreference.com/w/cpp/string/byte/isspace
	return char == ' ' || char == '\f' || char == '\n' || char == '\t' || char == '\r' || char == '\v'
}