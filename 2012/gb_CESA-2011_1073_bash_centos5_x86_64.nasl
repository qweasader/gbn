# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017767.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881347");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:33:34 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2008-5374");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:1073");
  script_name("CentOS Update for bash CESA-2011:1073 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"bash on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Bash is the default shell for Red Hat Enterprise Linux.

  It was found that certain scripts bundled with the Bash documentation
  created temporary files in an insecure way. A malicious, local user could
  use this flaw to conduct a symbolic link attack, allowing them to overwrite
  the contents of arbitrary files accessible to the victim running the
  scripts. (CVE-2008-5374)

  This update fixes the following bugs:

  * When using the source builtin at location '.', occasionally, bash
  opted to preserve internal consistency and abort scripts. This caused
  bash to abort scripts that assigned values to read-only variables.
  This is now fixed to ensure that such scripts are now executed as
  written and not aborted. (BZ#448508)

  * When the tab key was pressed for auto-completion options for the typed
  text, the cursor moved to an unexpected position on a previous line if
  the prompt contained characters that cannot be viewed and a '\]'. This
  is now fixed to retain the cursor at the expected position at the end of
  the target line after autocomplete options correctly display. (BZ#463880)

  * Bash attempted to interpret the NOBITS .dynamic section of the ELF
  header. This resulted in a '^D: bad ELF interpreter: No such
  file or directory' message. This is fixed to ensure that the invalid
  '^D' does not appear in the error message. (BZ#484809)

  * The $RANDOM variable in Bash carried over values from a previous
  execution for later jobs. This is fixed and the $RANDOM variable
  generates a new random number for each use. (BZ#492908)

  * When Bash ran a shell script with an embedded null character, bash's
  source builtin parsed the script incorrectly. This is fixed and
  bash's source builtin correctly parses shell script null characters.
  (BZ#503701)

  * The bash manual page for 'trap' did not mention that signals ignored upon
  entry cannot be listed later. The manual page was updated for this update
  and now specifically notes that 'Signals ignored upon entry to the shell
  cannot be trapped, reset or listed'. (BZ#504904)

  * Bash's readline incorrectly displayed additional text when resizing
  the terminal window when text spanned more than one line, which caused
  incorrect display output. This is now fixed to ensure that text in more
  than one line in a resized window displays as expected. (BZ#525474)

  * Previously, bash incorrectly displayed 'Broken pipe' messages for
  builtins like 'echo' and 'printf' when output did not succeed due to
  EPIPE. This is fixed t ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~3.2~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
