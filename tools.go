package ident

func stringSliceIncludes(slice []string, str string) bool {
	return stringSliceIndexOf(slice, str) != -1
}

func stringSliceIndexOf(slice []string, str string) int {
	for i, s := range slice {
		if s == str {
			return i
		}
	}
	return -1
}
