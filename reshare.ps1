#######################################################
##  Author: Brian Cole becole@brianecole.net         ##
##  Date: July 27, 2022                              ##
##                                                   ##
##  Purpose: Recreate shares that disappear at boot  ##
#######################################################

## $ShareFolderInfo = Folders to Share: Share Name, Path
## $GrantGroupAcc = Groups to grant access: Group Name, Access Level, Allow/Deny
## $RemoveACLs = Groups/users to remove from Security Tab

$ShareFolderInfo = @("Share1","C:\Test\Share1"), @("Share2","C:\Test\Share2")
$GrantGroupAcc = @("Group1", "FullControl", "Allow"), @("Group2", "FullControl", "Allow"), @("Group3", "FullControl", "Allow")
$RemoveACLs = @("Users", "Authenticated Users")

ForEach ($arrFolder in $ShareFolderInfo)
  {
    ##  Create Share  ##
    New-SMBShare -Name $arrFolder[0] -Path $arrFolder[1]
    ForEach ($arrGroup in $GrantGroupAcc)
      {
        ##  Remove Everyone from Sharing Permissions  ##
        Revoke-SmbShareAccess -Name $arrFolder[0] -AccountName 'Everyone' -Force
        ##  Add Users/Groups from $GrantGroupAcc  ##
        Grant-SmbShareAccess -Name $arrFolder[0] -AccountName $arrGroup[0] -AccessRight Full -force
        $acl = Get-Acl $arrFolder[1]
        ##  Disable Inheritance and Remove Users/Groups from Security Tab  ##
        $acl.SetAccessRuleProtection($True,$False)
        $acl.Access | %{$acl.RemoveAccessRule($_)}  
        ForEach ($arrGroup in $GrantGroupAcc)
          {
            ##  Add Users/Groups to Security Tab  ##
            $ace = New-Object System.Security.Accesscontrol.FileSystemAccessRule ($arrGroup)
            $acl.AddAccessRule($ace)
            Set-Acl -Path $arrFolder[1] -AclObject $acl
          }
      }
  }







