#include "MyPack.h"
#include <DbgHelp.h>
#include <time.h>
#pragma comment(lib,"DbgHelp.lib")

 // ��ȡPEͷ�����Ϣ
PIMAGE_DOS_HEADER MyPack::GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS MyPack::GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase +GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER MyPack::GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER MyPack::GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

// �����ļ�/�ڴ����
DWORD MyPack::Align(DWORD size, DWORD n)
{
	return size / n == 0 ? n : (size / n + 1)*n;
}

//�����ļ���,���ļ�������ΪPE���
void MyPack::LoadFile(LPCSTR fileName)
{
	// 1 ���ļ����ھʹ�,�򿪽�Ϊ�˶�ȡ�ļ�����
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, NULL,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 ��ȡ�ļ���С,���ô˴�С���뻺����
	m_fileSize = GetFileSize(hFile, NULL);
	m_fileBase = (DWORD)calloc(m_fileSize, sizeof(BYTE));//calloc ���벢��ʼ��
	// 3 ���ļ����ݶ�ȡ��������
	DWORD readSize = 0;// ʵ�ʶ�ȡ�Ĵ�С
	ReadFile(hFile, (LPVOID)m_fileBase, m_fileSize, &readSize, NULL);
	// 4 ��ֹ���й¶,�رվ��
	CloseHandle(hFile);

	return;
}
void MyPack::LoadStub(LPCSTR fileName)
{
	// 1 �Բ�ִ��dllMain�ķ�ʽ,����ģ�鵽��ǰ���ڴ���
	m_dllBase = (DWORD)LoadLibraryExA(fileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// 2 ��dll�л�ȡstart�����ĵ�ַ
	DWORD startAddr = (DWORD)GetProcAddress((HMODULE)m_dllBase, "Start");
	// 3 ����start�����Ķ���ƫ��,���յ�ַ=���ػ�ַ+���λ�ַ+����ƫ��
	m_startOffset = startAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
	// 4 ��ȡdll�����Ĺ���ӿ�,ͨ���˽ӿڿ�ʵ�����ݹ���(��ַ����޸�
	m_pShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dllBase, "shareData");//here
	//m_pShareData = (PSubConf)GetProcAddress((HMODULE)m_dllBase, "g_conf");
}

// ���߸��Ƶ�ǰ��,ʵ�����������
void MyPack::CopySection(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	// 1 ��ȡ����ͷ�����һ������ͷ�ĵ�ַ
	auto pLastSection = &IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase))[GetFileHeader(m_fileBase)->NumberOfSections - 1];
	// 2 ��������+1(�ļ�ͷ��
	GetFileHeader(m_fileBase)->NumberOfSections += 1;
	// 3 ͨ�����һ������ͷ,�ҵ����������ͷ��λ��,�����0
	auto pNewSection = pLastSection + 1;
	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	// 4 ��dll�л�ȡ�追����Դ����
	auto srcSection = GetSection(m_dllBase, srcSectionName);
	// 5 ֱ�ӽ�Դ���ε���Ϣ��������/Ŀ��������(��������������,ֻ�����ּ���
	memcpy(pNewSection, srcSection, sizeof(IMAGE_SECTION_HEADER));
	// 6 ����������ͷ���ֶ�:��������
	memcpy(pNewSection->Name, dstSectionName, 7);// ��memcpy����strcpy; �ܹ�8�ֽ�,����7,Ԥ��һ����\0
	// 7 ��������������RVA = ��һ������RVA��+ ��������ڴ��С
	pNewSection->VirtualAddress = pLastSection->VirtualAddress + Align(pLastSection->Misc.VirtualSize, GetOptHeader(m_fileBase)->SectionAlignment);
	// 8 ��������������FOA = ��һ������FOA + ��������ļ���С
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + Align(pLastSection->SizeOfRawData, GetOptHeader(m_fileBase)->FileAlignment);
	// 9 ���������ε��ļ���С���ڴ��С(������ȼ���
	//pNewSection->SizeOfRawData = pNewSection->Misc.VirtualSize = 0x200;
	// 10 ���¼����ļ��������С= ���һ������FOA + ���ļ���С,����ԭ�ļ����ݱ�������
	m_fileSize = pNewSection->PointerToRawData + pNewSection->SizeOfRawData;
	m_fileBase = (DWORD)realloc((void *)m_fileBase, m_fileSize);// ֮������allco����new,����Ϊ�˺��������realloc
	// 11 �޸��ļ����ڴ��С = ���һ������RVA + ���ڴ��С
	GetOptHeader(m_fileBase)->SizeOfImage = pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize;
	
	return;
}

// ��������κ���ļ����Ϊ���ļ�
void MyPack::SaveFile(LPCSTR fileName)
{
	// 1 �����ļ�,��ȡ���(д�ļ�/���۴�����������
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 ���ڴ��е��ļ�����д�����ļ���
	DWORD writeSize = 0;// ʵ��д���С
	WriteFile(hFile, (LPVOID *)m_fileBase, m_fileSize, &writeSize, NULL);
	// �ر��ļ�����Է�ֹй¶
	CloseHandle(hFile);

	return;
}

// ��ȡ����ͷ��Ϣ(����ͷ�ṹ��
PIMAGE_SECTION_HEADER MyPack::GetSection(DWORD fileBase, LPCSTR sectionName)
{
	// 1 ��ȡ����ͷ��(����һ��)
	auto sectionTable = IMAGE_FIRST_SECTION(GetNtHeader(fileBase));
	// 2 ��ȡ����ͷ���Ԫ�ظ���
	WORD sectionNumber = GetFileHeader(fileBase)->NumberOfSections;
	// 3 ��������ͷ��,�Ƚ�������,��������ͷ���ڵ�ַ(������������
	for (int i = 0; i < sectionNumber; i++)
	{
		// 4 ��memcpy����strcmp,ǰ�߿�ָ���Ƚϳ���,������\0Ϊ׼
		if (!memcmp(sectionName, sectionTable[i].Name, strlen(sectionName) + 1))
			return &sectionTable[i];
	}
	// 5 ��δ�ҵ�,�򷵻�null
	return NULL;
}

// ��������OEP
void MyPack::SetOEP()
{
	// 1 �޸�OEPǰ,��ԭʼOEP��������(�ɹ����dll,������ͨ����ַ����޸�
	m_pShareData->origOEP = GetOptHeader(m_fileBase)->AddressOfEntryPoint;//here
	//m_pShareData->srcOep = GetOptHeader(m_fileBase)->AddressOfEntryPoint;
	// 2 ������չͷ��OEP�ֶ�, ��OEP= start ����ƫ��+�����λ�ַ
	GetOptHeader(m_fileBase)->AddressOfEntryPoint = m_startOffset + GetSection(m_fileBase, ".pack")->VirtualAddress;
	return;
}

// ��������������(���߿�����ǰ��
void MyPack::CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	// 1 ��ȡԴ����������ռ��еĵ�ַ(ӳ��,LoadLibrary��ȡ��
	BYTE * pSrcData = (BYTE *)(GetSection(m_dllBase,".text")->VirtualAddress + m_dllBase);
	// 2 ��ȡĿ������������ռ��еĵ�ַ(����,ReadFile��ȡ��
	BYTE * pDstData = (BYTE *)(GetSection(m_fileBase, ".pack")->PointerToRawData + m_fileBase);
	// 3 Դӳ�񿽱���Ŀ�ľ���
	memcpy(pDstData, pSrcData, GetSection(m_dllBase, ".text")->SizeOfRawData);

	return;
}

// �޸�dll�Ǵ�����Ҫ�ض�λ�ĵط�
void MyPack::FixDllReloc()
{
	DWORD size = 0, oldProtect = 0;
	// 1 ��ȡdll���ض�λ��
	auto pRelocTable = (PIMAGE_BASE_RELOCATION)ImageDirectoryEntryToData((LPVOID)m_dllBase, TRUE, 5, &size);
	// 2 ѭ��,ֱ��Ϊ0�ض�λ�����
	while (pRelocTable->SizeOfBlock)
	{
		// 3 ����Ҫ�ض�λ�������ڴ����,���޸����������(ҳΪ��λ0x1000,
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + m_dllBase), 0x1000, PAGE_READWRITE, &oldProtect);
		// 4 ��ȡ�ض�λ��������׵�ַ ���ض�λ�������
		TypeOffset * pRelocItem = (TypeOffset *)pRelocTable + 1;//+1 �����ض�λ�ṹ��
		int relocItemCount = (pRelocTable->SizeOfBlock - 8) / 2;
		// 5 ������ǰ�ض�λ�������е��ض�λ��
		for (int i = 0; i < relocItemCount; i++)
		{
			// 6 type==3��ʾ��Ҫ�����ض�λ,��������
			if (pRelocItem[i].Type == 3)
			{
				// 7 ��ȡ��Ҫ�����ض�λ�ĵ�ַ���ڵ�λ��
				DWORD * pAddr = (DWORD *)(m_dllBase + pRelocTable->VirtualAddress + pRelocItem[i].Offset);
				// 8 ���������Ķ���ƫ��=���յ�ַ - dll �ļ����ػ�ַ - .text ���λ�ַ
				DWORD offsetInSection = *pAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
				// 9 �޸���ַ,�µ�ַ = ����ƫ��+ exe �ļ����ػ�ַ + ������.pack��ַ
				*pAddr = offsetInSection + GetOptHeader(m_fileBase)->ImageBase + GetSection(m_fileBase, ".pack")->VirtualAddress;
			}
		}
		// 10 ��ԭ���εı�������
		VirtualProtect((LPVOID)(pRelocTable->VirtualAddress + m_dllBase), 0x1000, oldProtect, &oldProtect);
		// 11 ��һ���ض�λ��
		pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocTable + pRelocTable->SizeOfBlock);
	}
	// 12 �ر�Դ������ض�λ,�������޸���dll�Ǵ����ض�λ,���Ǳ�ʾԴ����֧���ض�λ
	GetOptHeader(m_fileBase)->DllCharacteristics = 0x8100;

	return;
}

// ��������(������//here
void MyPack::EncodeSection(LPCSTR sectionName)
{
	// 1 ��Ҫ���ܵ�����(Դ��������
	auto pSection = GetSection(m_fileBase, ".text");
	// 2 �����������ڵ�λ��
	BYTE * pSectionData = (BYTE*)pSection->PointerToRawData + m_fileBase;
	// 3 ����ʱ��Ҫ����Ϣ(�����dll�Ǵ���
	srand((unsigned int)time(0));
	m_pShareData->key = rand() % 0xff;
	m_pShareData->rva = pSection->VirtualAddress;
	m_pShareData->size = pSection->SizeOfRawData;
	// 4 ѭ��,��λ����������
	for (int i = 0; i < m_pShareData->size; i++)
	{
		pSectionData[i] ^= m_pShareData->key;
	}
	return;
}
