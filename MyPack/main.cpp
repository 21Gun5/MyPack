#include "MyPack.h"

int main()
{
	MyPack pack;

	// 1. ��PE�ļ���ȡ���ڴ�
	pack.LoadFile("demo.exe");
	// 2. ���������
	pack.AddSection(".pack");
	// 3. ���Ϊ���ļ�
	pack.SaveFile("demo_pack.exe");

	return 0;
}