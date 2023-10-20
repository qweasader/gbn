# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

###############################################################################
# CLASS: Win32_Process Functions
#
# - wmi_proc_prop() - Returns List of all process with Properties.
# - wmi_proc_all()      - Returns Name of all process.
# - wmi_proc_path() - Returns installed path of the process.
#
# If procName = "svchost.exe", returns details of the Process
#
##############################################################################

function wmi_proc_prop(handle, procName)
{
  if(!procName){
    query = "Select * from Win32_Process";
  }
  else {
    query = 'Select * from Win32_Process Where Name = ' +
             raw_string(0x22) + procName + raw_string(0x22);
  }

  procList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< procList) || !procList){
    return(0);
  }

  return wmi_misc_split_res(List:procList);
}

function wmi_proc_all(handle, procName)
{
  if(!procName){
    query = "Select Caption from Win32_Process";
  }
  else {
    query = 'Select Caption from Win32_Process Where Name = ' +
             raw_string(0x22) + procName +raw_string(0x22);
  }

  procList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< procName) || !procList){
    return(0);
  }

  procList = ereg_replace(pattern:"\|[0-9a-zA-Z]+", string:procList, replace:"");
  return procList;
}

function wmi_proc_path(handle, procName)
{
  if(!procName){
    query = "Select ExecutablePath from Win32_Process";
  }
  else {
    query = 'Select ExecutablePath from Win32_Process Where Name = ' +
             raw_string(0x22) + procName + raw_string(0x22);
  }

  procList = wmi_query(wmi_handle:handle, query:query);

  if(("NTSTATUS" >< procList) || !procList){
    return(0);
  }

  procList = ereg_replace(pattern:"\|[0-9a-zA-Z]+", string:procList, replace:"");
  return procList;
}
