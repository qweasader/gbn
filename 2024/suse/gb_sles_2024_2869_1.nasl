# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2869.1");
  script_tag(name:"creation_date", value:"2024-08-12 04:24:46 +0000 (Mon, 12 Aug 2024)");
  script_version("2024-08-12T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-12 05:05:37 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2869-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2869-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242869-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca-certificates-mozilla' package(s) announced via the SUSE-SU-2024:2869-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ca-certificates-mozilla fixes the following issues:

Updated to 2.68 state of Mozilla SSL root CAs (bsc#1227525)
Added: FIRMAPROFESIONAL CA ROOT-A WEB

Distrust: GLOBALTRUST 2020


Updated to 2.66 state of Mozilla SSL root CAs (bsc#1220356)
 Added:

CommScope Public Trust ECC Root-01 CommScope Public Trust ECC Root-02 CommScope Public Trust RSA Root-01 CommScope Public Trust RSA Root-02 D-Trust SBR Root CA 1 2022 D-Trust SBR Root CA 2 2022 Telekom Security SMIME ECC Root 2021 Telekom Security SMIME RSA Root 2023 Telekom Security TLS ECC Root 2020 Telekom Security TLS RSA Root 2023 TrustAsia Global Root CA G3 TrustAsia Global Root CA G4
 Removed:
Autoridad de Certificacion Firmaprofesional CIF A62634068 Chambers of Commerce Root - 2008 Global Chambersign Root - 2008 Security Communication Root CA Symantec Class 1 Public Primary Certification Authority - G6 Symantec Class 2 Public Primary Certification Authority - G6 TrustCor ECA-1 TrustCor RootCert CA-1 TrustCor RootCert CA-2 VeriSign Class 1 Public Primary Certification Authority - G3 VeriSign Class 2 Public Primary Certification Authority - G3");

  script_tag(name:"affected", value:"'ca-certificates-mozilla' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~2.68~150200.33.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla-prebuilt", rpm:"ca-certificates-mozilla-prebuilt~2.68~150200.33.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~2.68~150200.33.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla-prebuilt", rpm:"ca-certificates-mozilla-prebuilt~2.68~150200.33.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~2.68~150200.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla-prebuilt", rpm:"ca-certificates-mozilla-prebuilt~2.68~150200.33.1", rls:"SLES15.0SP4"))) {
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
