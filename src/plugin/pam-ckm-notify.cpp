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
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int /*argc*/, const char **/*argv*/)
{
    if(flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;

    //for(int i=0; i<argc; i++)
    //    pam_syslog(pamh, LOG_ERR, "pam_sm_chauthtok arg %03d: %s\n", i, argv[i]);

    // identify user
    uid_t uid = -1;
    std::string passwd;
    if(identify_user_pwd(pamh, uid, passwd))
        return PAM_SESSION_ERR;
    pam_syslog(pamh, LOG_ERR, "<<change pwd>> uid: %d, pwd: \"%s\"\n", uid, passwd.c_str());

    return PAM_AUTHTOK_ERR;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ckm_notify");
#endif
