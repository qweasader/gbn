# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856034");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-1669", "CVE-2024-1670", "CVE-2024-1671", "CVE-2024-1672", "CVE-2024-1673", "CVE-2024-1674", "CVE-2024-1675", "CVE-2024-1676", "CVE-2024-2173", "CVE-2024-2174", "CVE-2024-2176", "CVE-2024-2400");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:31:14 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0084-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2LA5F4J2SLVEY6FKG6O3LFDSA2N3OMZH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issue:

     Chromium 122.0.6261.128 (boo#1221335)

  * CVE-2024-2400: Use after free in Performance Manager


     Chromium 122.0.6261.111 (boo#1220131,boo#1220604,boo#1221105)

  * New upstream security release.

  * CVE-2024-2173: Out of bounds memory access in V8.

  * CVE-2024-2174: Inappropriate implementation in V8.

  * CVE-2024-2176: Use after free in FedCM.

     Chromium 122.0.6261.94

  * CVE-2024-1669: Out of bounds memory access in Blink.

  * CVE-2024-1670: Use after free in Mojo.

  * CVE-2024-1671: Inappropriate implementation in Site Isolation.

  * CVE-2024-1672: Inappropriate implementation in Content Security Policy.

  * CVE-2024-1673: Use after free in Accessibility.

  * CVE-2024-1674: Inappropriate implementation in Navigation.

  * CVE-2024-1675: Insufficient policy enforcement in Download.

  * CVE-2024-1676: Inappropriate implementation in Navigation.

  * Type Confusion in V8");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"clang17", rpm:"clang17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-debuginfo", rpm:"clang17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-devel", rpm:"clang17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17", rpm:"libLLVM17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-debuginfo", rpm:"libLLVM17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLTO17", rpm:"libLTO17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLTO17-debuginfo", rpm:"libLTO17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17", rpm:"libclang-cpp17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-debuginfo", rpm:"libclang-cpp17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld17", rpm:"lld17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld17-debuginfo", rpm:"lld17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17", rpm:"llvm17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-debuginfo", rpm:"llvm17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-devel", rpm:"llvm17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-devel-debuginfo", rpm:"llvm17-devel-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-gold", rpm:"llvm17-gold~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-gold-debuginfo", rpm:"llvm17-gold-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libclang13", rpm:"llvm17-libclang13~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libclang13-debuginfo", rpm:"llvm17-libclang13-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly", rpm:"llvm17-polly~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly-debuginfo", rpm:"llvm17-polly-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly-devel", rpm:"llvm17-polly-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp17-devel", rpm:"libomp17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp17-devel-debuginfo", rpm:"libomp17-devel-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblldb17", rpm:"liblldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblldb17-debuginfo", rpm:"liblldb17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17", rpm:"lldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17-debuginfo", rpm:"lldb17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17-devel", rpm:"lldb17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++-devel", rpm:"llvm17-libc++-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++1", rpm:"llvm17-libc++1~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++1-debuginfo", rpm:"llvm17-libc++1-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi-devel", rpm:"llvm17-libc++abi-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi1", rpm:"llvm17-libc++abi1~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi1-debuginfo", rpm:"llvm17-libc++abi1-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lldb17", rpm:"python3-lldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-64bit", rpm:"libLLVM17-64bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-64bit-debuginfo", rpm:"libLLVM17-64bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-64bit", rpm:"libclang-cpp17-64bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-64bit-debuginfo", rpm:"libclang-cpp17-64bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-32bit", rpm:"libLLVM17-32bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-32bit-debuginfo", rpm:"libLLVM17-32bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-32bit", rpm:"libclang-cpp17-32bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-32bit-debuginfo", rpm:"libclang-cpp17-32bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-doc", rpm:"clang17-doc~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-doc", rpm:"llvm17-doc~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-opt-viewer", rpm:"llvm17-opt-viewer~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-vim-plugins", rpm:"llvm17-vim-plugins~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-clang17", rpm:"python3-clang17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17", rpm:"clang17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-debuginfo", rpm:"clang17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-devel", rpm:"clang17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17", rpm:"libLLVM17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-debuginfo", rpm:"libLLVM17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLTO17", rpm:"libLTO17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLTO17-debuginfo", rpm:"libLTO17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17", rpm:"libclang-cpp17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-debuginfo", rpm:"libclang-cpp17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld17", rpm:"lld17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld17-debuginfo", rpm:"lld17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17", rpm:"llvm17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-debuginfo", rpm:"llvm17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-devel", rpm:"llvm17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-devel-debuginfo", rpm:"llvm17-devel-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-gold", rpm:"llvm17-gold~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-gold-debuginfo", rpm:"llvm17-gold-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libclang13", rpm:"llvm17-libclang13~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libclang13-debuginfo", rpm:"llvm17-libclang13-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly", rpm:"llvm17-polly~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly-debuginfo", rpm:"llvm17-polly-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-polly-devel", rpm:"llvm17-polly-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp17-devel", rpm:"libomp17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp17-devel-debuginfo", rpm:"libomp17-devel-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~122.0.6261.128~bp155.2.75.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblldb17", rpm:"liblldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblldb17-debuginfo", rpm:"liblldb17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17", rpm:"lldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17-debuginfo", rpm:"lldb17-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb17-devel", rpm:"lldb17-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++-devel", rpm:"llvm17-libc++-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++1", rpm:"llvm17-libc++1~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++1-debuginfo", rpm:"llvm17-libc++1-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi-devel", rpm:"llvm17-libc++abi-devel~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi1", rpm:"llvm17-libc++abi1~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-libc++abi1-debuginfo", rpm:"llvm17-libc++abi1-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lldb17", rpm:"python3-lldb17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-64bit", rpm:"libLLVM17-64bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-64bit-debuginfo", rpm:"libLLVM17-64bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-64bit", rpm:"libclang-cpp17-64bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-64bit-debuginfo", rpm:"libclang-cpp17-64bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-32bit", rpm:"libLLVM17-32bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libLLVM17-32bit-debuginfo", rpm:"libLLVM17-32bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-32bit", rpm:"libclang-cpp17-32bit~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclang-cpp17-32bit-debuginfo", rpm:"libclang-cpp17-32bit-debuginfo~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang17-doc", rpm:"clang17-doc~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-doc", rpm:"llvm17-doc~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-opt-viewer", rpm:"llvm17-opt-viewer~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm17-vim-plugins", rpm:"llvm17-vim-plugins~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-clang17", rpm:"python3-clang17~17.0.6~bp155.2.2", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);