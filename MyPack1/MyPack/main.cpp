#include <windows.h>
#include <stdio.h>
#include "CPeFileOper.h"

int main()
{
	CPeFileOper m_Pe;		//PE�ļ����������

	char path[MAX_PATH] = "demo.exe";
	// 1. �򿪱��ӿǳ���
	int nTargetSize = 0;
	char* pTargetBuff = m_Pe.GetFileData(path, &nTargetSize);
		
	//����stub.dll
	StubInfo stub = { 0 };
	m_Pe.LoadStub(&stub);

	//������������
	m_Pe.Encrypt(pTargetBuff, stub);

	//�������Ŀ¼����
	m_Pe.ClearDataDir(pTargetBuff, stub);

	//���������
	char cNewSectionName[] = {"GuiShou"};		//��������
	m_Pe.AddSection(pTargetBuff, nTargetSize, cNewSectionName,
		m_Pe.GetSection(stub.dllbase,".text")->Misc.VirtualSize);

	//�޸��ض�λ
	m_Pe.FixStubRelocation((DWORD)stub.dllbase,
		m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress,
		m_Pe.GetOptionHeader(pTargetBuff)->ImageBase,
		m_Pe.GetSection(pTargetBuff, cNewSectionName)->VirtualAddress);

	//����Ŀ���ļ���OEP��stub��ȫ�ֱ�����
	stub.pStubConf->srcOep = m_Pe.GetOptionHeader(pTargetBuff)->AddressOfEntryPoint;

	//��stub.dll�Ĵ���θ��Ƶ��¼ӵ�GuiShou����
	memcpy(m_Pe.GetSection(pTargetBuff, cNewSectionName)->PointerToRawData+pTargetBuff,
		m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress+stub.dllbase,
		m_Pe.GetSection(stub.dllbase,".text")->Misc.VirtualSize);

	//�޸�OEP OEP=start(VA)-dll���ػ�ַ-����RVA+�����εĶ���RVA
	m_Pe.GetOptionHeader(pTargetBuff)->AddressOfEntryPoint=
		stub.pfnStart-(DWORD)stub.dllbase
		-m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress
		+m_Pe.GetSection(pTargetBuff, cNewSectionName)->VirtualAddress;

	//ȥ�������ַ
	m_Pe.GetOptionHeader(pTargetBuff)->DllCharacteristics &= (~0x40);

	//���汻�ӿǵĳ���
	m_Pe.SavePEFile(pTargetBuff,nTargetSize,"demo_pack.exe");

	return 0;
}