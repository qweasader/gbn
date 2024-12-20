# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.4063.1");
  script_tag(name:"creation_date", value:"2021-12-15 03:22:16 +0000 (Wed, 15 Dec 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:4063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:4063-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20214063-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu.691' package(s) announced via the SUSE-SU-2021:4063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icu.691 fixes the following issues:


Renamed package from icu 69.1 for SUSE:SLE-15-SP3:Update. (jsc#SLE-17893)

Fix undefined behaviour in 'ComplexUnitsConverter::applyRounder'

Update to release 69.1
 - For Norwegian, 'no' is back to being the canonical code, with 'nb'
 treated as equivalent. This aligns handling of Norwegian with other
 macro language codes.
 - Binary prefixes in measurement units (KiB, MiB, etc.)
 - Time zone offsets from local time with new APIs.

Don't disable testsuite under 'qemu-linux-user'

Fixed an issue when ICU test on 'aarch64 fails. (bsc#1182645)

Drop 'SUSE_ASNEEDED' as the issue was in binutils. (bsc#1182252)

Fix 'pthread' dependency issue. (bsc#1182252)

Update to release 68.2
 - Fix memory problem in 'FormattedStringBuilder'
 - Fix assertion when 'setKeywordValue w/' long value.
 - Fix UBSan breakage on 8bit of rbbi
 - fix int32_t overflow in listFormat
 - Fix memory handling in MemoryPool::operator=()
 - Fix memory leak in AliasReplacer

Add back icu.keyring.

Update to release 68.1
 - PluralRules selection for ranges of numbers
 - Locale ID canonicalization now conforms to the CLDR spec including
 edge cases
 - DateIntervalFormat supports output options such as capitalization
 - Measurement units are normalized in skeleton string output
 - Time zone data (tzdata) version 2020d

Add the provides for libicu to Make .Net core can install successfully.
 (bsc#1167603, bsc#1161007)

Update to version 67.1
 - Unicode 13 (ICU-20893, same as in ICU 66)
 - Total of 5930 new characters
 - 4 new scripts
 - 55 new emoji characters, plus additional new sequences
 - New CJK extension, first characters in plane 3: U+30000..U+3134A
 - New language at Modern coverage: Nigerian Pidgin
 - New languages at Basic coverage: Fulah (Adlam), Maithili, Manipuri,
 Santali, Sindhi (Devanagari), Sundanese
 - Region containment: EU no longer includes GB
 - Unicode 13 root collation data and Chinese data for collation and
 transliteration
 - DateTimePatternGenerator now obeys the 'hc' preference in the locale
 identifier
 - Various other improvements for ECMA-402 conformance
 - Number skeletons have a new 'concise' form that can be used in
 MessageFormat strings
 - Currency formatting options for formal and other currency display name
 variants
 - ListFormatter: new public API to select the style & type
 - ListFormatter now selects the proper 'and'/'or' form for
 Spanish & Hebrew.
 - Locale ID canonicalization upgraded to implement the complete CLDR
 spec.
 - LocaleMatcher: New option to ignore one-way matches
 - acceptLanguage() reimplemented via LocaleMatcher
 - Data build tool: tzdbNames.res moved from the 'zone_tree' category to
 the 'zone_supplemental' category
 - Fixed uses of u8'literals' broken by the C++20 introduction of the
 incompatible char8_t type
 - and added a few API overloads to reduce the need for reinterpret_cast.
 - Support for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'icu.691' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"icu.691", rpm:"icu.691~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu.691-debuginfo", rpm:"icu.691-debuginfo~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu.691-debugsource", rpm:"icu.691-debugsource~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu.691-devel", rpm:"icu.691-devel~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu.691-doc", rpm:"icu.691-doc~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu69", rpm:"libicu69~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu69-bedata", rpm:"libicu69-bedata~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu69-debuginfo", rpm:"libicu69-debuginfo~69.1~7.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu69-ledata", rpm:"libicu69-ledata~69.1~7.3.2", rls:"SLES15.0SP3"))) {
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
