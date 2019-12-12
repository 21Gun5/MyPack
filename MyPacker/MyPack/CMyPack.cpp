#include "CMyPack.h"
#include "CAES.h"

 // 获取PE头相关信息
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

//传入文件名,若文件存在且为PE则打开
void CMyPack::LoadFile(LPCSTR fileName)
{
	// 1 若文件存在就打开,打开仅为了读取文件数据
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 获取文件大小,并用此大小申请缓冲区
	m_fileSize = GetFileSize(hFile, NULL);
	m_fileBase = (DWORD)calloc(m_fileSize, sizeof(BYTE));//calloc 申请并初始化
	// 3 将文件内容读取到缓冲区
	DWORD readSize = 0;// 实际读取的大小
	ReadFile(hFile, (LPVOID)m_fileBase, m_fileSize, &readSize, NULL);
	// 4 防止句柄泄露,关闭句柄
	CloseHandle(hFile);
	return;
}
void CMyPack::LoadStub1(LPCSTR fileName)
{
	// 1 以不执行dllMain的方式,加载模块到当前的内存中
	m_dllBase = (DWORD)LoadLibraryExA(fileName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	// 2 从dll中获取start函数的地址
	DWORD startAddr = (DWORD)GetProcAddress((HMODULE)m_dllBase, "Start");
	// 3 计算start函数的段内偏移,最终地址=加载基址+区段基址+段内偏移
	m_startOffset = startAddr - m_dllBase - GetSection(m_dllBase, ".text")->VirtualAddress;
	// 4 获取dll导出的共享接口,通过此接口可实现数据共享(地址间接修改
	m_pShareData = (PSHAREDATA)GetProcAddress((HMODULE)m_dllBase, "shareData");//here
}

// 获取区段头信息(区段头结构体
PIMAGE_SECTION_HEADER CMyPack::GetSection(DWORD fileBase, LPCSTR sectionName)
{
	// 1 获取区段头表(即第一项)
	auto sectionTable = IMAGE_FIRST_SECTION(GetNtHeader(fileBase));

	// 2 获取区段头表的元素个数

	WORD sectionNumber = GetFileHeader(fileBase)->NumberOfSections;

	// 3 遍历区段头表,比较其名称,返回区段头所在地址(而非真正区段

	for (int i = 0; i < sectionNumber; i++)

	{

		// 4 用memcpy而非strcmp,前者可指定比较长度,后者以\0为准

		if (!memcmp(sectionName, sectionTable[i].Name, strlen(sectionName) + 1))

			return &sectionTable[i];

	}

	// 5 若未找到,则返回null

	return NULL;

}

// 获取最后一个区段
IMAGE_SECTION_HEADER* CMyPack::GetLastSection()
{
	//获取区段个数
	DWORD dwScnCount = GetFileHeader(m_fileBase)->NumberOfSections;
	//获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase));
	//得到最后一个有效区段
	return pScn + (dwScnCount - 1);
}

// 进行文件/内存对齐
int CMyPack::AlignMent(_In_ int size, _In_ int alignment)
{
	return (size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
}

// 添加新区段
void CMyPack::AddSection(LPCSTR dstSectionName, LPCSTR srcSectionName)
{
	int scnSize = GetSection(m_dllBase, ".text")->Misc.VirtualSize;
	//增加文件头的区段个数
	GetFileHeader(m_fileBase)->NumberOfSections++;
	//配置新区段的区段头
	IMAGE_SECTION_HEADER* pNewScn = NULL;
	pNewScn = GetLastSection();
	//区段的名字
	memcpy(pNewScn->Name, dstSectionName,8);
	//区段的大小(实际大小/对齐后的大小)
	pNewScn->Misc.VirtualSize = scnSize;
	pNewScn->SizeOfRawData = AlignMent(scnSize,GetOptHeader(m_fileBase)->FileAlignment);
	//区段的位置(RVA/FOA)
	pNewScn->PointerToRawData = AlignMent(m_fileSize, GetOptHeader(m_fileBase)->FileAlignment);
	//新区段的内存偏移=上一个区段的内存偏移+上一个区段的大小(内存对齐后的大小)------------------

	pNewScn->VirtualAddress = (pNewScn - 1)->VirtualAddress + AlignMent((pNewScn-1)->SizeOfRawData, GetOptHeader(m_fileBase)->SectionAlignment);
	
	//区段的属性
	pNewScn->Characteristics = 0xE00000E0;

	//修改扩展头的映像大小
	GetOptHeader(m_fileBase)->SizeOfImage =pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	//扩充文件数据的堆空间大小
	int newSize = pNewScn->PointerToRawData + pNewScn->SizeOfRawData;
	char* pNewBuff = new char[newSize]{0};
	memcpy(pNewBuff,(char *)m_fileBase, m_fileSize);
	//释放旧的缓冲区
	delete (char *)m_fileBase;

	//将新的缓冲区首地址和新文件的大小赋给形参(修改实参)
	m_fileSize = newSize;
	m_fileBase = (DWORD)pNewBuff;
}

// 对所有区段加密
void CMyPack::Encrypt()
{

	unsigned char key[] =
	{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	};

	//初始化aes对象
	CAES aes(key);

	//获取区段数量
	//DWORD dwSectionCount = GetFileHead(pFileData)->NumberOfSections;
	DWORD dwSectionCount = GetFileHeader(m_fileBase)->NumberOfSections;
	//获取第一个区段
	//IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	IMAGE_SECTION_HEADER* pFirstSection = IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase));
	//用于保存数据
	//pStub.pStubConf->data[20][2] = { 0 };
	//pStub.pStubConf->index = 0;
	m_pShareData->data[20][2] = { 0 };
	m_pShareData->index = 0;

	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		DWORD dwIsRsrc = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".rsrc");
		DWORD dwIsTls = lstrcmp((LPCWSTR)pFirstSection[i].Name, (LPCWSTR)".tls");

		//资源段和tls段不加密并跳过无效的区段
		if (dwIsRsrc == 0 || dwIsTls == 0 || pFirstSection[i].PointerToRawData == 0 || pFirstSection[i].SizeOfRawData == 0)
		{
			continue;
		}
		else       //开始加密所有区段
		{
			//获取区段的首地址和大小
			//BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)pFileData;
			BYTE* pTargetSection = pFirstSection[i].PointerToRawData + (BYTE*)m_fileBase;
			DWORD dwTargetSize = pFirstSection[i].SizeOfRawData;

			//修改属性为可写
			DWORD dwOldAttr = 0;
			VirtualProtect(pTargetSection, dwTargetSize, PAGE_EXECUTE_READWRITE, &dwOldAttr);
			//加密目标区段
			aes.Cipher(pTargetSection, dwTargetSize);
			//修改回原来的属性
			VirtualProtect(pTargetSection, dwTargetSize, dwOldAttr, &dwOldAttr);

			//保存数据到共享信息结构体
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

// 清除数据目录表
void CMyPack::ClearDataDir()
{
	//获取数据目录表的个数
	DWORD dwNumOfDataDir = GetOptHeader(m_fileBase)->NumberOfRvaAndSizes;
	//保存数据目录表的个数
	m_pShareData->dwNumOfDataDir = dwNumOfDataDir;
	//初始化保存数据目录表的结构体
	m_pShareData->dwDataDir[20][2] = 0;
	//遍历数据目录表
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i==2)
		{
			continue;
		}
		//保存数据目录表的数据
		m_pShareData->dwDataDir[i][0] = GetOptHeader(m_fileBase)->DataDirectory[i].VirtualAddress;
		m_pShareData->dwDataDir[i][1] = GetOptHeader(m_fileBase)->DataDirectory[i].Size;
		//清除数据目录表项
		GetOptHeader(m_fileBase)->DataDirectory[i].VirtualAddress = 0;
		GetOptHeader(m_fileBase)->DataDirectory[i].Size = 0;
	}
}

// 修复stub重定位
void CMyPack::FixStubRelocation()
 {
	 DWORD stubTextRva = GetSection(m_dllBase, ".text")->VirtualAddress;
	 DWORD targetDllbase = GetOptHeader(m_fileBase)->ImageBase;
	 DWORD targetNewScnRva = GetSection(m_fileBase, ".pack")->VirtualAddress;
	//找到stub.dll的重定位表
	 DWORD dwRelRva = GetOptHeader(m_dllBase)->DataDirectory[5].VirtualAddress;
	 IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva+ m_dllBase);
	
	 //遍历重定位表
	 while (pRel->SizeOfBlock)
	 {
		 struct TypeOffset
		 {
			 WORD offset : 12;
			 WORD type : 4;
		 };
		 TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		 DWORD dwCount = (pRel->SizeOfBlock-8)/2;	//需要重定位的数量
		 for (DWORD i = 0; i < dwCount; i++)
		 {
			 if (pTypeOffset[i].type!=3)
			 {
				 continue;
			 }
			 //需要重定位的地址
			 DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + m_dllBase);
			 DWORD dwOld;
			 //修改属性为可写
			 VirtualProtect(pFixAddr,4,PAGE_READWRITE,&dwOld);
			 //去掉dll当前加载基址
			 *pFixAddr -= m_dllBase;
			 //去掉默认的段首RVA
			 *pFixAddr -= stubTextRva;
			 //换上目标文件的加载基址
			 *pFixAddr += targetDllbase;
			 //加上新区段的段首RVA
			 *pFixAddr += targetNewScnRva;
			 //把属性修改回去
			 VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		 }
		 //切换到下一个重定位块
		 pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	 }
 }

// 设置新区段内容(后者拷贝至前者
void CMyPack::CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName)

{

	// 1 获取源区段在虚拟空间中的地址(映像,LoadLibrary获取的

	BYTE * pSrcData = (BYTE *)(GetSection(m_dllBase, ".text")->VirtualAddress + m_dllBase);

	// 2 获取目的区段在物理空间中的地址(镜像,ReadFile获取的

	BYTE * pDstData = (BYTE *)(GetSection(m_fileBase, ".pack")->PointerToRawData + m_fileBase);

	// 3 源映像拷贝至目的镜像

	memcpy(pDstData, pSrcData, GetSection(m_dllBase, ".text")->SizeOfRawData);



	return;

}

// 重新设置OEP
void CMyPack::SetOEP()
{
	// 1 修改OEP前,将原始OEP保存下来(可共享给dll,本质是通过地址间接修改
	m_pShareData->srcOep = GetOptHeader(m_fileBase)->AddressOfEntryPoint;
	// 2 设置扩展头中OEP字段, 新OEP= start 段内偏移+新区段基址
	GetOptHeader(m_fileBase)->AddressOfEntryPoint = m_startOffset + GetSection(m_fileBase, ".pack")->VirtualAddress;
	return;
}

// 将添加区段后的文件另存为新文件
void CMyPack::SaveFile(LPCSTR fileName)
{
	// 1 创建文件,获取句柄(写文件/无论存在与否均创建
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 将内存中的文件数据写入新文件中
	DWORD writeSize = 0;// 实际写入大小
	WriteFile(hFile, (LPVOID *)m_fileBase, m_fileSize, &writeSize, NULL);
	// 关闭文件句柄以防止泄露
	CloseHandle(hFile);
	return;
}

// 取消随机基址
void CMyPack::CancelRandomBase()
{
	GetOptHeader(m_fileBase)->DllCharacteristics &= (~0x40);
}