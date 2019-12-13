#include "MyPack.h"

int main()
{
	MyPack pack;
	// 1 ��ȡ�ļ����ڴ�
	pack.LoadExeFile("demo.exe");
	//pack.LaodFile("TLSTest3.exe");//here
	pack.LoadDllStub("MyStub.dll");
	// 2 ���������
	pack.AddSection(".pack", ".text");
	pack.AddSection(".stu_re", ".reloc");
	// 3 ��������OEP
	pack.SetOEP();
	// 4 ���������
	pack.SetClearImport();
	// 5 �ض�λ���
	pack.FixReloc();// �޸����ض�λ
	pack.FixReloc2();// ��dll���ض�λ�������������޸�VirtualAddress��
	pack.SetRelocTable();// �޸�Ŀ������ض�λ���λ�õ����ض�λ��.stu_re��
	// 6 �������Ŀ¼��
	//pack.ClearDataDirTab();//here
	// 7 ѹ������
	char * ptmp = (char *)".text";
	pack.CompressSection(ptmp);//
	// 8 ��������
	//pack.XorSection(".text");// ������
	pack.EncryptAllSection();//AES������������
	// 9 �������������
	pack.CopySectionData(".pack", ".text");
	pack.CopySectionData(".stu_re", ".reloc");
	// 10 ���Ϊ���ļ�
	pack.SaveFile("demo_pack.exe");
	//pack.SaveFile("TLSTest3_pack.exe");
	return 0;
}