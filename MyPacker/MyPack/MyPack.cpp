#include <stdio.h>
#include <time.h>
#include "MyPack.h"
#include "lz4.h"
#include "AES.h"
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")

// ��ȡPEͷ�����Ϣ
PIMAGE_DOS_HEADER MyPack::DosHeader(DWORD Base)
{
	return (PIMAGE_DOS_HEADER)Base;
}
PIMAGE_NT_HEADERS MyPack::NtHeader(DWORD Base)
{
	return (PIMAGE_NT_HEADERS)(Base + DosHeader(Base)->e_lfanew);
}
PIMAGE_FILE_HEADER MyPack::FileHeader(DWORD Base)
{
	return &NtHeader(Base)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER MyPack::OptHeader(DWORD Base)
{
	return &NtHeader(Base)->OptionalHeader;
}

// �ڴ�/�ļ�����
DWORD MyPack::Alignment(DWORD n, DWORD align)
{
	return n % align == 0 ? n : (n / align + 1) * align;
}

// ��ȡ����ͷ��Ϣ(����ͷ�ṹ��
PIMAGE_SECTION_HEADER MyPack::GetSection(DWORD Base, LPCSTR SectionName)
{
	// 1. ��ȡ�����α�ĵ�һ��
	auto SectionTable = IMAGE_FIRST_SECTION(NtHeader(Base));

	// 2. ��ȡ�����α��Ԫ�ظ���
	WORD SectionCount = FileHeader(Base)->NumberOfSections;

	// 3. �������α��Ƚ����ε����ƣ�����������Ϣ�ṹ��ĵ�ַ
	for (WORD i = 0; i < SectionCount; ++i)
	{
		// ����ҵ���ֱ�ӷ���
		if (!memcmp(SectionName, SectionTable[i].Name, strlen(SectionName) + 1))
			return &SectionTable[i];
	}

	return nullptr;
}

// ��ȡĿ�����
VOID MyPack::LoadExeFile(LPCSTR FileName)
{
	// ����ļ����ڣ��ʹ��ļ����򿪵�Ŀ��ֻ��Ϊ�˶�ȡ���е�����
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��ȡ�ļ��Ĵ�С����ʹ�������С���뻺����
	FileSize = GetFileSize(FileHandle, NULL);
	FileBase = (DWORD)calloc(FileSize, sizeof(BYTE));

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Read = 0;
	ReadFile(FileHandle, (LPVOID)FileBase, FileSize, &Read, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);
}

// ��ȡ�Ǵ���
VOID MyPack::LoadDllStub(LPCSTR FileName)
{
	// �Բ�ִ�� DllMain �ķ�ʽ����ģ�鵽��ǰ���ڴ���
	DllBase = (DWORD)LoadLibraryExA(FileName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	// �� dll �л�ȡ�� start ����������������ҳ��ƫ��(���ػ�ַ + ���λ�ַ + ����ƫ��)
	DWORD Start = (DWORD)GetProcAddress((HMODULE)DllBase, "start");
	StartOffset = Start - DllBase - GetSection(DllBase, ".text")->VirtualAddress;

	// ��ȡ��������Ϣ
	ShareData = (PSHAREDATA)GetProcAddress((HMODULE)DllBase, "ShareData");
}

// ���������
VOID MyPack::AddSection(LPCSTR SectionName, LPCSTR SrcName)
{
	// 1. ��ȡ�����α�����һ��Ԫ�صĵ�ַ
	auto LastSection = &IMAGE_FIRST_SECTION(NtHeader(FileBase))
		[FileHeader(FileBase)->NumberOfSections - 1];

	// 2. ���ļ�ͷ�б������������ + 1
	FileHeader(FileBase)->NumberOfSections += 1;

	// 3. ͨ�����һ�����Σ��ҵ�����ӵ����ε�λ��
	auto NewSection = LastSection + 1;
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));

	// 4.  �� dll ���ҵ�������Ҫ����������
	auto SrcSection = GetSection(DllBase, SrcName);

	// 5. ֱ�ӽ�Դ���ε�������Ϣ�������µ�������
	memcpy(NewSection, SrcSection, sizeof(IMAGE_SECTION_HEADER));

	// 6. �����µ����α��е����ݣ� ����
	memcpy(NewSection->Name, SectionName, 7);

	// 7. �����µ��������ڵ� RVA = ��һ�����ε�RVA + ������ڴ��С
	NewSection->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, OptHeader(FileBase)->SectionAlignment);

	// 8. �����µ��������ڵ� FOA = ��һ�����ε�FOA + ������ļ���С
	NewSection->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, OptHeader(FileBase)->FileAlignment);

	// 9. ���¼����ļ��Ĵ�С�������µĿռ䱣��ԭ�е�����
	FileSize = NewSection->SizeOfRawData + NewSection->PointerToRawData;
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 11. �޸� SizeOfImage �Ĵ�С = ���һ�����ε�RVA + ���һ�����ε��ڴ��С
	OptHeader(FileBase)->SizeOfImage = NewSection->VirtualAddress + NewSection->Misc.VirtualSize;
}

// ������ļ�
VOID MyPack::SaveFile(LPCSTR FileName)
{
	// �����ļ��Ƿ���ڣ���Ҫ�����µ��ļ�
	HANDLE FileHandle = CreateFileA(FileName, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// ��Ŀ���ļ������ݶ�ȡ�������Ļ�������
	DWORD Write = 0;
	WriteFile(FileHandle, (LPVOID)FileBase, FileSize, &Write, NULL);

	// Ϊ�˷�ֹ���й¶Ӧ�ùرվ��
	CloseHandle(FileHandle);
}

// ����OEP
VOID MyPack::SetOEP()
{
	// �޸�ԭʼ oep ֮ǰ������ oep
	ShareData->OldOep = OptHeader(FileBase)->AddressOfEntryPoint;

	// --------------------AddressOfEntryPoint----------------------

	// �µ� rav = start �Ķ���ƫ�� + �����ε� rva
	OptHeader(FileBase)->AddressOfEntryPoint = StartOffset +
		GetSection(FileBase, ".pack")->VirtualAddress;
}

// �������������
VOID MyPack::CopySectionData(LPCSTR SectionName, LPCSTR SrcName)
{
	// ��ȡԴ����������ռ�(dll->ӳ��)�еĻ�ַ
	BYTE* SrcData = (BYTE*)(GetSection(DllBase, SrcName)->VirtualAddress + DllBase);

	// ��ȡĿ������������ռ�(��->����)�еĻ�ַ
	BYTE* DestData = (BYTE*)(GetSection(FileBase, SectionName)->PointerToRawData + FileBase);

	// ֱ�ӽ����ڴ濽��
	memcpy(DestData, SrcData, GetSection(DllBase, SrcName)->SizeOfRawData);
}

// �޸����ض�λ
VOID MyPack::FixReloc()
{
	DWORD Size = 0, OldProtect = 0;

	// ��ȡ��������ض�λ��
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);

	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, PAGE_READWRITE, &OldProtect);

		// ����ض�λ�ض�λ�ķ�ҳ��ַ
		// printf("RVA: %08X\n", RealocTable->VirtualAddress);

		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// ����ÿһ���ض�λ��������
		for (int i = 0; i < count; ++i)
		{
			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
			if (to[i].Type == 3)
			{
				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				DWORD* addr = (DWORD*)(DllBase + RealocTable->VirtualAddress + to[i].Offset);

				// ���������Ķ���ƫ�� = *addr - imagebase - .text va
				DWORD item = *addr - DllBase - GetSection(DllBase, ".text")->VirtualAddress;

				// ʹ�������ַ��������µ��ض�λ�������
				*addr = item + OptHeader(FileBase)->ImageBase + GetSection(FileBase, ".pack")->VirtualAddress;
				// printf("\t%08x - %08X - %08X\n", addr, *addr, item);
			}
		}

		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(RealocTable->VirtualAddress + DllBase),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	// �رճ�����ض�λ��Ŀǰֻ���޸��˿Ǵ�����ض�λ��������ʾԴ����֧���ض�λ
	OptHeader(FileBase)->DllCharacteristics = 0x8100;
}

// �����ض�λ��
VOID MyPack::FixReloc2()
{
	DWORD Size = 0, OldProtect = 0;

	// ��ȡ��������ض�λ��
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);

	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
		// �ض�λ��VirtualAddress �ֶν����޸ģ���Ҫ���ض�λ���ɿ�д
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, &OldProtect);

		// ����VirtualAddress���ӿ��е�text�� Ŀ�����pack��
		// �޸���ʽ ��VirtualAddress - ��.text.VirtualAddress  + Ŀ�����.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSection(DllBase, ".text")->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(FileBase, ".pack")->VirtualAddress;



		// ��ԭԭ���εĵı�������
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	return;
}

// �޸�Ŀ���������Ŀ����ض�λ���λ�õ����ض�λ��.stu_re��
VOID MyPack::SetRelocTable()
{
	// ��ȡԭʼ������ض�λ�����б���
	ShareData->oldRelocRva =
		NtHeader(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress;

	// �޸��ض�λ���µ����� ��stu_re��
	NtHeader(FileBase)->OptionalHeader.DataDirectory[5].VirtualAddress
		= GetSection(FileBase, ".stu_re")->VirtualAddress;

	// �޸��ض�λ��С  Ŀ��.director[5].size = ��.director[5].size;
	NtHeader(FileBase)->OptionalHeader.DataDirectory[5].Size =
		NtHeader(DllBase)->OptionalHeader.DataDirectory[5].Size;

	// �ó���֧���ض�λ
	NtHeader(FileBase)->FileHeader.Characteristics &= 0xFFFFFFFE;
	NtHeader(FileBase)->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// ����ԭʼ���ػ�ַ�����޸�ʱʹ��
	ShareData->oldImageBase = NtHeader(FileBase)->OptionalHeader.ImageBase;

	return VOID();
}

// ����������
VOID MyPack::XorSection(LPCSTR SectionName)
{
	// 1. ��ȡ����Ҫ���ܵ����ε���Ϣ
	auto XorSection = GetSection(FileBase, ".text");

	// 2. �ҵ���Ҫ���ܵ��ֶ������ڴ��е�λ��
	BYTE* data = (BYTE*)(XorSection->PointerToRawData + FileBase);

	// 3. ��д����ʱ��Ҫ�ṩ����Ϣ
	srand((unsigned int)time(0));
	ShareData->key = rand() % 0xff;
	ShareData->rva = XorSection->VirtualAddress;
	ShareData->size = XorSection->SizeOfRawData;

	// 4. ѭ����ʼ���м���
	for (int i = 0; i < ShareData->size; ++i)
	{
		data[i] ^= ShareData->key;
	}

}

// ѹ������
bool MyPack::CompressSection(char * SectionName)
{
	// ��ȡ���������Ϣ
	PIMAGE_SECTION_HEADER pSection = GetSection(FileBase, SectionName);
	// ѹ��ǰλ��
	char * pRoffset = (char*)(pSection->PointerToRawData + FileBase);
	// �������ļ��еĴ�С
	long lSize = pSection->SizeOfRawData;

	// 0 ����ѹ��ǰ��Ϣ
	// ѹ�����ݵ�RVA
	ShareData->FrontCompressRva = pSection->VirtualAddress;
	// ѹ��ǰ��СSize
	ShareData->FrontCompressSize = lSize;

	// ---------------------------------��ʼѹ��
	// 1 ��ȡԤ����ѹ������ֽ���:
	int compress_size = LZ4_compressBound(lSize);
	// 2. �����ڴ�ռ�, ���ڱ���ѹ���������
	char* pBuff = new char[compress_size];
	// 3. ��ʼѹ���ļ�����(��������ѹ����Ĵ�С)
	ShareData->LaterCompressSize = LZ4_compress(
		pRoffset,/*ѹ��ǰ������*/
		pBuff, /*ѹ���������*/
		lSize/*�ļ�ԭʼ��С*/);

	// 4.��ѹ��������ݸ���ԭʼ����
	memcpy(pRoffset, pBuff, ShareData->LaterCompressSize);

	// 5.�޸���ǰ�����ļ���С 
	pSection->SizeOfRawData = Alignment(ShareData->LaterCompressSize, 0x200);

	// 6.������������������
	PIMAGE_SECTION_HEADER pFront = pSection;
	PIMAGE_SECTION_HEADER pLater = pSection + 1;
	// û�к�һ�����Σ��Ͳ���Ҫ����
	while (pLater->VirtualAddress)
	{
		// ��ǰ���δ�С
		long DesSize = pFront->SizeOfRawData;
		// �ƶ���������κ���
		char * pDest = (char*)(pFront->PointerToRawData + FileBase + DesSize);

		// �¸����δ�С
		long SrcSize = pLater->SizeOfRawData;
		// ��һ������λ��
		char * pSrc = (char*)(pLater->PointerToRawData + FileBase);

		// ��������
		memcpy(pDest, pSrc, SrcSize);

		// �޸��¸�����λ�� ����FileBase��ӦΪ�������ڴ���
		pLater->PointerToRawData = pFront->PointerToRawData + DesSize;

		// ���������¸�����
		pFront += 1;
		pLater += 1;
	}

	// 7.�����޸��ļ�ʵ�ʴ�С
	// ʵ�ʴ�С = ���һ������λ�� + ������δ�С
	FileSize = pFront->PointerToRawData + pFront->SizeOfRawData;

	// 8.�����޸��ļ���С
	FileBase = (DWORD)realloc((VOID*)FileBase, FileSize);

	// 9.�ͷſռ�
	delete[]pBuff;

	return true;
}

// ���������
VOID MyPack::SetClearImport()
{
	// 1 ���浼���
	PIMAGE_NT_HEADERS pNt = NtHeader(FileBase);
	ShareData->ImportRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	// 2 ��յ����
	pNt->OptionalHeader.DataDirectory[1].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[1].Size = 0;
	// 3 ���IAT��
	pNt->OptionalHeader.DataDirectory[12].VirtualAddress = 0;
	pNt->OptionalHeader.DataDirectory[12].Size = 0;
	return;
}

// AES������������
void MyPack::EncryptAllSection()
{
	unsigned char key1[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//��ʼ��aes����
	CAES aes(key1);

	//��ȡ��������
	DWORD dwSectionCount = FileHeader(FileBase)->NumberOfSections;
	//��ȡ��һ������
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(NtHeader(FileBase));
	//���ڱ�������
	ShareData->data[20][2] = { 0 };
	ShareData->index = 0;

	//DWORD dwIsTls = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".reloc");
	//DWORD dwIsTls2 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".data");
	//DWORD dwIsTls4 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".stu_re");
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls3 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rdata");
		DWORD dwIsTls1 = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".pack");


		//������Դ ֻ������ ������
		if (dwIsRsrc == 0 || dwIsTls1 == 0 || dwIsTls3 == 0)// || pFirstSection[i].PointerToRawData == 0 || pFirstSection[i].SizeOfRawData == 0
		{
			continue;
		}
		else       //��ʼ������������
		{
			//��ȡ���ε��׵�ַ�ʹ�С
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)FileBase;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//�޸�����Ϊ��д
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//����Ŀ������
			aes.Cipher(pTargetSection, dwTargetSize);
			//�޸Ļ�ԭ��������
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//�������ݵ�������Ϣ�ṹ��
			ShareData->data[ShareData->index][0] = pFirstSection[i].VirtualAddress;
			ShareData->data[ShareData->index][1] = dwTargetSize;
			ShareData->index++;
		}
	}
	memcpy(ShareData->key1, key1, 16);
}

// �������Ŀ¼��
void MyPack::ClearDataDirTab()
{
	// 0 ��ʼ���������: ��������Ŀ¼����Ϣ
	ShareData->dwDataDir[20][2] = 0;
	// 1 ��ȡ����Ԫ�ظ���������(һ��Ϊ16
	DWORD dwNumOfDataDir = OptHeader(FileBase)->NumberOfRvaAndSizes;
	ShareData->dwNumOfDataDir = dwNumOfDataDir;
	// 3 ��������Ŀ¼��
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		// 4 ������Դ��
		if (i == 2)
		{
			continue;
		}
		// 5 ��������Ŀ¼����Ϣ: RVA/Size
		ShareData->dwDataDir[i][0] = OptHeader(FileBase)->DataDirectory[i].VirtualAddress;
		ShareData->dwDataDir[i][1] = OptHeader(FileBase)->DataDirectory[i].Size;
		// 6 �������Ŀ¼����
		OptHeader(FileBase)->DataDirectory[i].VirtualAddress = 0;
		OptHeader(FileBase)->DataDirectory[i].Size = 0;
	}
}

