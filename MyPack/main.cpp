#include "MyPack.h"

int main()
{
	MyPack pack;

	// 1. 将PE文件读取到内存
	pack.LoadFile("demo.exe");
	// 2. 添加新区段
	pack.AddSection(".pack");
	// 3. 另存为新文件
	pack.SaveFile("demo_pack.exe");

	return 0;
}