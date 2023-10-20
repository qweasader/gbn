# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1420");
  script_cve_id("CVE-2014-9938", "CVE-2015-7545", "CVE-2016-2315", "CVE-2016-2324", "CVE-2017-1000117", "CVE-2017-14867", "CVE-2018-11235", "CVE-2018-17456");
  script_tag(name:"creation_date", value:"2020-01-23 11:44:01 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-23T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-06-23 05:05:08 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 15:18:00 +0000 (Wed, 21 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for git (EulerOS-SA-2019-1420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1420");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1420");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'git' package(s) announced via the EulerOS-SA-2019-1420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2, 2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution can occur. With a crafted .gitmodules file, a malicious project can execute an arbitrary script on a machine that runs 'git clone --recurse-submodules' because submodule 'names' are obtained from this file, and then appended to $GIT_DIR/modules, leading to directory traversal with '../' in a name. Finally, post-checkout hooks from a submodule are executed, bypassing the intended design in which hooks are not obtained from a remote server.(CVE-2018-11235)

A shell command injection flaw related to the handling of 'ssh' URLs has been discovered in Git. An attacker could use this flaw to execute shell commands with the privileges of the user running the Git client, for example, when performing a 'clone' action on a malicious repository or a legitimate repository containing a malicious commit.(CVE-2017-1000117)

Git before 2.10.5, 2.11.x before 2.11.4, 2.12.x before 2.12.5, 2.13.x before 2.13.6, and 2.14.x before 2.14.2 uses unsafe Perl scripts to support subcommands such as cvsserver, which allows attackers to execute arbitrary OS commands via shell metacharacters in a module name. The vulnerable code is reachable via git-shell even without CVS support.(CVE-2017-14867)

It was found that the git-prompt.sh script shipped with git failed to correctly handle branch names containing special characters. A specially crafted git repository could use this flaw to execute arbitrary commands if a user working with the repository configured their shell to include repository information in the prompt.(CVE-2014-9938)

An integer truncation flaw and an integer overflow flaw, both leading to a heap-based buffer overflow, were found in the way Git processed certain path information. A remote attacker could create a specially crafted Git repository that would cause a Git client or server to crash or, possibly, execute arbitrary code.(CVE-2016-2324)

A flaw was found in the way the git-remote-ext helper processed certain URLs. If a user had Git configured to automatically clone submodules from untrusted repositories, an attacker could inject commands into the URL of a submodule, allowing them to execute arbitrary code on the user's system.(CVE-2015-7545)

Git before 2.14.5, 2.15.x before 2.15.3, 2.16.x before 2.16.5, 2.17.x before 2.17.2, 2.18.x before 2.18.1, and 2.19.x before 2.19.1 allows remote code execution during processing of a recursive 'git clone' of a superproject if a .gitmodules file has a URL field beginning with a '-' character.(CVE-2018-17456)

An integer truncation flaw and an integer overflow flaw, both leading to a heap-based buffer overflow, were found in the way Git processed certain path information. A remote attacker could create a specially crafted Git repository that would cause a Git client or server to crash or, possibly, execute arbitrary code.(CVE-2016-2315)");

  script_tag(name:"affected", value:"'git' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~1.8.3.1~20.h1", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~1.8.3.1~20.h1", rls:"EULEROSVIRT-3.0.1.0"))) {
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
