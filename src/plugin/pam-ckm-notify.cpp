#include <sys/param.h>

#include <string>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <symbol-visibility.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <syslog.h>
#include <shadow.h>
#include <ckm/ckm-control.h>

namespace
{
std::string old_password;

bool identify_user(pam_handle_t *pamh, uid_t & uid)
{
    int pam_err;
    const char *user;
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return NULL;
    struct passwd *pwd;
    if ((pwd = getpwnam(user)) == NULL)
        return true;
    uid = pwd->pw_uid;
    return false;
}

bool identify_user_pwd(pam_handle_t *pamh, uid_t & uid, std::string & passwd)
{
    int pam_err;
    const char *user;
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return NULL;
    struct passwd *pwd;
    if ((pwd = getpwnam(user)) == NULL)
        return true;
    if(strcmp(pwd->pw_passwd, "x")==0)
    {
        struct spwd *pwd_sh;
        if ((pwd_sh = getspnam(user)) == NULL)
            return true;
        passwd = std::string(pwd_sh->sp_pwdp);
    }
    else
        passwd = std::string(pwd->pw_passwd);
    uid = pwd->pw_uid;
    return false;
}
}

COMMON_API PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_SESSION_ERR;

    int ec = CKM::Control::create()->unlockUserKey(uid, passwd.c_str());
    if(ec == CKM_API_SUCCESS)
        return PAM_SUCCESS;

    // TODO: key-manager<->system password desync
    pam_syslog(pamh, LOG_ERR, "error initializing key-manager session, ec: %d\n", ec);

    return PAM_SESSION_ERR;
}

COMMON_API PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    // identify user
    uid_t uid = -1;
    if(identify_user(pamh, uid))
        return PAM_SESSION_ERR;

    if(CKM::Control::create()->lockUserKey(uid) == CKM_API_SUCCESS)
        return PAM_SUCCESS;

    return PAM_SESSION_ERR;
}

COMMON_API PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if(argc==0) {
        pam_syslog(pamh, LOG_ERR, "key-manager plugin called with inappropriate arguments\n");
        return PAM_SERVICE_ERR;
    }

    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_USER_UNKNOWN;

    for(int cntr=0; cntr<argc; cntr++)
    {
        if(!strstr(argv[cntr], "change_step"))
            continue;

        if(strstr(argv[0], "before"))
        {
            if( ! (flags & PAM_PRELIM_CHECK))
                old_password = passwd;
            return PAM_SUCCESS;
        }
        else if(strstr(argv[0], "after"))
        {
            if(flags & PAM_PRELIM_CHECK)
                return PAM_SUCCESS;

            if(old_password.size() == 0) {
                pam_syslog(pamh, LOG_ERR, "attempt to change key-manager password w/o old password\n");
                // return PAM_SERVICE_ERR; // PAM will ignore the error code,
                                           // calling app will get wrong result information
                return PAM_SUCCESS;
            }
            std::string local_old_pwd = old_password;
            old_password.clear();

            // CKM does not allow to change user password if database does
            // not exists. We must create database before change password.
            auto ctrl = CKM::Control::create();
            if (CKM_API_SUCCESS != ctrl->unlockUserKey(uid, local_old_pwd.c_str())) {
                // no DB reset here: somebody else might have changed password in mean time
                // if desync happened, next login attempt will remove the DB

                // return PAM_SERVICE_ERR; // PAM will ignore the error code,
                                           // calling app will get wrong result information
            }

            int ec = ctrl->changeUserPassword(uid, local_old_pwd.c_str(), passwd.c_str());
            if (CKM_API_SUCCESS != ec) {
                pam_syslog(pamh, LOG_ERR, "attempt to change key-manager password ec: %d\n", ec);
                // return PAM_SERVICE_ERR; // PAM will ignore the error code,
                                           // calling app will get wrong result information
            }

            return PAM_SUCCESS;
        }
        break;
    }

    pam_syslog(pamh, LOG_ERR, "key-manager plugin called with no valid \"change_step\" option setting\n");
    return PAM_SERVICE_ERR;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ckm_notify");
#endif
