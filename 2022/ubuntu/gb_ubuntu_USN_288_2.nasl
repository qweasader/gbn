# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.288.2");
  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-288-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-288-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-288-2");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/techdocs.50");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1' package(s) announced via the USN-288-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-288-1 fixed two vulnerabilities in Ubuntu 5.04 and Ubuntu 5.10.
This update fixes the same vulnerabilities for Ubuntu 6.06 LTS.

For reference, these are the details of the original USN:

 CVE-2006-2313:
 Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling of
 invalidly-encoded multibyte text data. If a client application
 processed untrusted input without respecting its encoding and applied
 standard string escaping techniques (such as replacing a single quote
 >>'<< with >>\'<< or >>''<<), the PostgreSQL server could interpret the
 resulting string in a way that allowed an attacker to inject arbitrary
 SQL commands into the resulting SQL query. The PostgreSQL server has
 been modified to reject such invalidly encoded strings now, which
 completely fixes the problem for some 'safe' multibyte encodings like
 UTF-8.

 CVE-2006-2314:
 However, there are some less popular and client-only multibyte
 encodings (such as SJIS, BIG5, GBK, GB18030, and UHC) which contain
 valid multibyte characters that end with the byte 0x5c, which is the
 representation of the backslash character >>\<< in ASCII. Many client
 libraries and applications use the non-standard, but popular way of
 escaping the >>'<< character by replacing all occurrences of it with
 >>\'<<. If a client application uses one of the affected encodings and
 does not interpret multibyte characters, and an attacker supplies a
 specially crafted byte sequence as an input string parameter, this
 escaping method would then produce a validly-encoded character and
 an excess >>'<< character which would end the string. All subsequent
 characters would then be interpreted as SQL code, so the attacker
 could execute arbitrary SQL commands.

 To fix this vulnerability end-to-end, client-side applications must
 be fixed to properly interpret multibyte encodings and use >>''<<
 instead of >>\'<<. However, as a precautionary measure, the sequence
 >>\'<< is now regarded as invalid when one of the affected client
 encodings is in use. If you depend on the previous behaviour, you
 can restore it by setting 'backslash_quote = on' in postgresql.conf.
 However, please be aware that this could render you vulnerable
 again.

 This issue does not affect you if you only use single-byte (like
 SQL_ASCII or the ISO-8859-X family) or unaffected multibyte (like
 UTF-8) encodings.

 Please see [link moved to references] for further
 details.");

  script_tag(name:"affected", value:"'postgresql-8.1' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"8.1.4-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq4", ver:"8.1.4-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.4-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-8.1", ver:"8.1.4-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-8.1", ver:"8.1.4-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
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
