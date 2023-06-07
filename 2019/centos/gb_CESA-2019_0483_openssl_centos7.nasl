# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883021");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2018-5407");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 16:58:00 +0000 (Fri, 18 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-03-21 09:50:45 +0100 (Thu, 21 Mar 2019)");
  script_name("CentOS Update for openssl CESA-2019:0483 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0483");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-March/023219.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the CESA-2019:0483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and
Transport Layer Security (TLS) protocols, as well as a full-strength
general-purpose cryptography library.

Security Fix(es):

  * openssl: Side-channel vulnerability on SMT/Hyper-Threading architectures
(PortSmash) (CVE-2018-5407)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * Perform the RSA signature self-tests with SHA-256 (BZ#1673914)");

  script_tag(name:"affected", value:"openssl on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2k~16.el7_6.1", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.2k~16.el7_6.1", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.2k~16.el7_6.1", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.2k~16.el7_6.1", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.2k~16.el7_6.1", rls:"CentOS7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

  if(__pkg_match) exit(99);
  exit(0);
}
