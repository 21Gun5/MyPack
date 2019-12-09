#include "MyPack.h"

int main()
{
	MyPack pack;

	// 1 ������ļ���ȡ���ڴ�
	pack.LoadFile("demo.exe");// Դ�ļ�
	pack.LoadStub("MyStub.dll");// �Ǵ���
	// 2 ���߸��Ƶ�ǰ��,ʵ�����������ͷ
	pack.CopySection(".pack",".text");
	// 3 ����OEP(Ϊstart ������ַ
	pack.SetOEP();
	// 4 �ԿǴ���dll�����ݽ����ض�λ
	pack.FixDllReloc();
	// 5 ��������(������
	pack.EncodeSection(".text");
	// 6 ��������������(���߿�����ǰ��
	pack.CopySectionData(".pack",".text");
	// 7 ���Ϊ���ļ�
	pack.SaveFile("demo_pack.exe");

	return 0;
}