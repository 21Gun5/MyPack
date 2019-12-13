#include "MyPack.h"

int main()
{
	MyPack pack;
	// 1 读取文件到内存
	pack.LoadExeFile("demo.exe");
	//pack.LaodFile("TLSTest3.exe");//here
	pack.LoadDllStub("MyStub.dll");
	// 2 添加新区段
	pack.AddSection(".pack", ".text");
	pack.AddSection(".stu_re", ".reloc");
	// 3 重新设置OEP
	pack.SetOEP();
	// 4 操作导入表
	pack.SetClearImport();
	// 5 重定位相关
	pack.FixReloc();// 修复壳重定位
	pack.FixReloc2();// 对dll的重定位进行修正（仅修改VirtualAddress）
	pack.SetRelocTable();// 修改目标程序重定位表的位置到新重定位表（.stu_re）
	// 6 清空数据目录表
	//pack.ClearDataDirTab();//here
	// 7 压缩区段
	char * ptmp = (char *)".text";
	pack.CompressSection(ptmp);//
	// 8 加密区段
	//pack.XorSection(".text");// 异或加密
	pack.EncryptAllSection();//AES加密所有区段
	// 9 填充新区段内容
	pack.CopySectionData(".pack", ".text");
	pack.CopySectionData(".stu_re", ".reloc");
	// 10 另存为新文件
	pack.SaveFile("demo_pack.exe");
	//pack.SaveFile("TLSTest3_pack.exe");
	return 0;
}