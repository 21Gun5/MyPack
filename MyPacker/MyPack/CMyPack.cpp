#include "CMyPack.h"
#include "CAES.h"

 // ��ȡPEͷ�����Ϣ
PIMAGE_DOS_HEADER CMyPack::GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS CMyPack::GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase + GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER CMyPack::GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER CMyPack::GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

//�����ļ���,���ļ�������ΪPE���
void CMyPack::LoadFile(LPCSTR fileName)
{
	// 1 ���ļ����ھʹ�,�򿪽�Ϊ�˶�ȡ�ļ�����
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
void CMyPack::LoadStub1(LPCSTR fileName)
{
	// 1 �Բ�ִ��dllMain�ķ�ʽ,����ģ�鵽��ǰ���ڴ���
	m_dllBase = (DWORD)LoadLibraryExA(fileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// 2 ��dll�л�ȡstart�����ĵ�ַ
	DWORD startAddr = (DWORD)GetProcAddress((HMODULE)m_dllBase, "Start");
	// 3 ����start�����Ķ���ƫ��,���յ�ַ=���ػ�ַ+���λ�ַ+����ƫ��
	m_startOffset = startAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
	// 4 ��ȡdll�����Ĺ���ӿ�,ͨ���˽ӿڿ�ʵ�����ݹ���(��ַ����޸�
	m_pShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dllBase, "shareData");//here
}

// ��ȡ����ͷ��Ϣ(����ͷ�ṹ��
PIMAGE_SECTION_HEADER CMyPack::GetSection(DWORD fileBase, LPCSTR sectionName)
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

// ��ȡ���һ������
IMAGE_SECTION_HEADER* CMyPack::GetLastSection()
{
	//��ȡ���θ���
	DWORD dwScnCount = GetFileHeader(m_fileBase)->NumberOfSections;
	//��ȡ��һ������
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase));
	//�õ����һ����Ч����
	return pScn + (dwScnCount - 1);
}

// �����ļ�/�ڴ����
int CMyPack::AlignMent(_In_ int size, _In_ int alignment)
{
	return (size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
}

// ���������
void CMyPack::AddSection(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	int scnSize = GetSection(m_dllBase, ".text")->Misc.VirtualSize;
	//�����ļ�ͷ�����θ���
	GetFileHeader(m_fileBase)->NumberOfSections++;
	//���������ε�����ͷ
	IMAGE_SECTION_HEADER* pNewScn = NULL;
	pNewScn = GetLastSection();
	//���ε�����
	memcpy(pNewScn->Name, dstSectionName,8);
	//���εĴ�С(ʵ�ʴ�С/�����Ĵ�С)
	pNewScn->Misc.VirtualSize = scnSize;
	pNewScn->SizeOfRawData = AlignMent(scnSize,GetOptHeader(m_fileBase)->FileAlignment);
	//���ε�λ��(RVA/FOA)
	pNewScn->PointerToRawData = AlignMent(m_fileSize, GetOptHeader(m_fileBase)->FileAlignment);
	//�����ε��ڴ�ƫ��=��һ�����ε��ڴ�ƫ��+��һ�����εĴ�С(�ڴ�����Ĵ�С)------------------

	pNewScn->VirtualAddress = (pNewScn - 1)->VirtualAddress + AlignMent((pNewScn-1)->SizeOfRawData, GetOptHeader(m_fileBase)->SectionAlignment);
	
	//���ε�����
	pNewScn->Characteristics = 0xE00000E0;

	//�޸���չͷ��ӳ���С
	GetOptHeader(m_fileBase)->SizeOfImage =pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	//�����ļ����ݵĶѿռ��С
	int newSize = pNewScn->PointerToRawData + pNewScn->SizeOfRawData;
	char* pNewBuff = new char[newSize]{0};
	memcpy(pNewBuff,(char *)m_fileBase, m_fileSize);
	//�ͷžɵĻ�����
	delete (char *)m_fileBase;

	//���µĻ������׵�ַ�����ļ��Ĵ�С�����β�(�޸�ʵ��)
	m_fileSize = newSize;
	m_fileBase = (DWORD)pNewBuff;
}

// ���������μ���
void CMyPack::Encrypt()
{

	unsigned char key[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//��ʼ��aes����
	CAES aes(key);

	//��ȡ��������
	//DWORD dwSectionCount = GetFileHead(pFileData)->NumberOfSections;
	DWORD dwSectionCount = GetFileHeader(m_fileBase)->NumberOfSections;
	//��ȡ��һ������
	//IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase));
	//���ڱ�������
	//pStub.pStubConf->data[20][2] = { 0 };
	//pStub.pStubConf->index = 0;
	m_pShareData->data[20][2] = { 0 };
	m_pShareData->index = 0;

	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".tls");

		//��Դ�κ�tls�β����ܲ�������Ч������
		if (dwIsRsrc == 0 || dwIsTls == 0 || pFirstSection[i].PointerToRawData == 0 || pFirstSection[i].SizeOfRawData == 0)
		{
			continue;
		}
		else       //��ʼ������������
		{
			//��ȡ���ε��׵�ַ�ʹ�С
			//BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)pFileData;
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)m_fileBase;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//�޸�����Ϊ��д
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//����Ŀ������
			aes.Cipher(pTargetSection, dwTargetSize);
			//�޸Ļ�ԭ��������
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//�������ݵ�������Ϣ�ṹ��
			//pStub.pStubConf->data[pStub.pStubConf->index][0] = pFirstSection[i].VirtualAddress;
			//pStub.pStubConf->data[pStub.pStubConf->index][1] = dwTargetSize;
			//pStub.pStubConf->index++;
			m_pShareData->data[m_pShareData->index][0] = pFirstSection[i].VirtualAddress;
			m_pShareData->data[m_pShareData->index][1] = dwTargetSize;
			m_pShareData->index++;
		}
	}
	//memcpy(pStub.pStubConf->key, key, 16);
	memcpy(m_pShareData->key, key, 16);
}

// �������Ŀ¼��
void CMyPack::ClearDataDir()
{
	//��ȡ����Ŀ¼��ĸ���
	DWORD dwNumOfDataDir = GetOptHeader(m_fileBase)->NumberOfRvaAndSizes;
	//��������Ŀ¼��ĸ���
	m_pShareData->dwNumOfDataDir = dwNumOfDataDir;
	//��ʼ����������Ŀ¼��Ľṹ��
	m_pShareData->dwDataDir[20][2] = 0;
	//��������Ŀ¼��
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i==2)
		{
			continue;
		}
		//��������Ŀ¼�������
		m_pShareData->dwDataDir[i][0] = GetOptHeader(m_fileBase)->DataDirectory[i].VirtualAddress;
		m_pShareData->dwDataDir[i][1] = GetOptHeader(m_fileBase)->DataDirectory[i].Size;
		//�������Ŀ¼����
		GetOptHeader(m_fileBase)->DataDirectory[i].VirtualAddress = 0;
		GetOptHeader(m_fileBase)->DataDirectory[i].Size = 0;
	}
}

// �޸�stub�ض�λ
void CMyPack::FixStubRelocation()
 {
	 DWORD stubTextRva = GetSection(m_dllBase, ".text")->VirtualAddress;
	 DWORD targetDllbase = GetOptHeader(m_fileBase)->ImageBase;
	 DWORD targetNewScnRva = GetSection(m_fileBase, ".pack")->VirtualAddress;
	//�ҵ�stub.dll���ض�λ��
	 DWORD dwRelRva = GetOptHeader(m_dllBase)->DataDirectory[5].VirtualAddress;
	 IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva+ m_dllBase);
	
	 //�����ض�λ��
	 while (pRel->SizeOfBlock)
	 {
		 struct TypeOffset
		 {
			 WORD offset : 12;
			 WORD type : 4;
		 };
		 TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		 DWORD dwCount = (pRel->SizeOfBlock-8)/2;	//��Ҫ�ض�λ������
		 for (DWORD i = 0; i < dwCount; i++)
		 {
			 if (pTypeOffset[i].type!=3)
			 {
				 continue;
			 }
			 //��Ҫ�ض�λ�ĵ�ַ
			 DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + m_dllBase);
			 DWORD dwOld;
			 //�޸�����Ϊ��д
			 VirtualProtect(pFixAddr,4,PAGE_READWRITE,&dwOld);
			 //ȥ��dll��ǰ���ػ�ַ
			 *pFixAddr -= m_dllBase;
			 //ȥ��Ĭ�ϵĶ���RVA
			 *pFixAddr -= stubTextRva;
			 //����Ŀ���ļ��ļ��ػ�ַ
			 *pFixAddr += targetDllbase;
			 //���������εĶ���RVA
			 *pFixAddr += targetNewScnRva;
			 //�������޸Ļ�ȥ
			 VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		 }
		 //�л�����һ���ض�λ��
		 pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	 }
 }

// ��������������(���߿�����ǰ��
void CMyPack::CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName)

{

	// 1 ��ȡԴ����������ռ��еĵ�ַ(ӳ��,LoadLibrary��ȡ��

	BYTE * pSrcData = (BYTE *)(GetSection(m_dllBase, ".text")->VirtualAddress + m_dllBase);

	// 2 ��ȡĿ������������ռ��еĵ�ַ(����,ReadFile��ȡ��

	BYTE * pDstData = (BYTE *)(GetSection(m_fileBase, ".pack")->PointerToRawData + m_fileBase);

	// 3 Դӳ�񿽱���Ŀ�ľ���

	memcpy(pDstData, pSrcData, GetSection(m_dllBase, ".text")->SizeOfRawData);



	return;

}

// ��������OEP
void CMyPack::SetOEP()
{
	// 1 �޸�OEPǰ,��ԭʼOEP��������(�ɹ����dll,������ͨ����ַ����޸�
	m_pShareData->srcOep = GetOptHeader(m_fileBase)->AddressOfEntryPoint;
	// 2 ������չͷ��OEP�ֶ�, ��OEP= start ����ƫ��+�����λ�ַ
	GetOptHeader(m_fileBase)->AddressOfEntryPoint = m_startOffset + GetSection(m_fileBase, ".pack")->VirtualAddress;
	return;
}

// ��������κ���ļ����Ϊ���ļ�
void CMyPack::SaveFile(LPCSTR fileName)
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

// ȡ�������ַ
void CMyPack::CancelRandomBase()
{
	GetOptHeader(m_fileBase)->DllCharacteristics &= (~0x40);
}