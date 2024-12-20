# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882486");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-10 05:19:51 +0200 (Tue, 10 May 2016)");
  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107",
                "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openssl CESA-2016:0722 centos7");
  script_tag(name:"summary", value:"Check the version of openssl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols,
as well as a full-strength general-purpose cryptography library.

Security Fix(es):

  * A flaw was found in the way OpenSSL encoded certain ASN.1 data
structures. An attacker could use this flaw to create a specially crafted
certificate which, when verified or re-encoded by OpenSSL, could cause it
to crash, or execute arbitrary code using the permissions of the user
running an application compiled against the OpenSSL library.
(CVE-2016-2108)

  * Two integer overflow flaws, leading to buffer overflows, were found in
the way the EVP_EncodeUpdate() and EVP_EncryptUpdate() functions of OpenSSL
parsed very large amounts of input data. A remote attacker could use these
flaws to crash an application using OpenSSL or, possibly, execute arbitrary
code with the permissions of the user running that application.
(CVE-2016-2105, CVE-2016-2106)

  * It was discovered that OpenSSL leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when the connection used the
AES CBC cipher suite and the server supported AES-NI. A remote attacker
could possibly use this flaw to retrieve plain text from encrypted packets
by using a TLS/SSL or DTLS server as a padding oracle. (CVE-2016-2107)

  * Several flaws were found in the way BIO_*printf functions were
implemented in OpenSSL. Applications which passed large amounts of
untrusted data through these functions could crash or potentially execute
code with the permissions of the user running such an application.
(CVE-2016-0799, CVE-2016-2842)

  * A denial of service flaw was found in the way OpenSSL parsed certain
ASN.1-encoded data from BIO (OpenSSL's I/O abstraction) inputs. An
application using OpenSSL that accepts untrusted ASN.1 BIO input could be
forced to allocate an excessive amount of data. (CVE-2016-2109)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2016-2108, CVE-2016-2842, CVE-2016-2105, CVE-2016-2106, CVE-2016-2107,
and CVE-2016-0799. Upstream acknowledges Huzaifa Sidhpurwala (Red Hat),
Hanno Bock, and David Benjamin (Google) as the original reporters of
CVE-2016-2108  Guido Vranken as the original reporter of CVE-2016-2842,
CVE-2016-2105, CVE-2016-2106, and CVE-2016-0799  and Juraj Somorovsky as
the original reporter of CVE-2016-2107.");
  script_tag(name:"affected", value:"openssl on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0722");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021860.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~51.el7_2.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~51.el7_2.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~51.el7_2.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~51.el7_2.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~51.el7_2.5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
