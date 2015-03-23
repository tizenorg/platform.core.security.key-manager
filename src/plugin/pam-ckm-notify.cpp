#include <sys/param.h>

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

struct passwd *identify_user_pwd(pam_handle_t *pamh)
{
    int pam_err;
    const char *user;
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return NULL;
    struct passwd *pwd;
    if ((pwd = getpwnam(user)) == NULL)
        return NULL;
    if(strcmp(pwd->pw_passwd, "x")==0)
    {
        struct spwd *pwd_sh;
        if ((pwd_sh = getspnam(user)) == NULL)
            return NULL;
        //pam_syslog(pamh, LOG_ERR, "<<shadow>> username: \"%s\", pwd: \"%s\" --> shadow: \"%s\"\n", pwd_sh->sp_namp, pwd->pw_passwd, pwd_sh->sp_pwdp);
    }
    return pwd;
}

COMMON_API PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    pam_syslog(pamh, LOG_ERR, "enter pam_sm_open_session\n");

    // identify user
    struct passwd *current_user = identify_user_pwd(pamh);
    if(!current_user)
        return PAM_SESSION_ERR;
    pam_syslog(pamh, LOG_ERR, "<<login>> username: \"%s\", pwd: \"%s\", uid: %d\n", current_user->pw_name, current_user->pw_passwd, current_user->pw_uid);

    return PAM_SUCCESS;
}

COMMON_API PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int /*flags*/, int /*argc*/, const char **/*argv*/)
{
    pam_syslog(pamh, LOG_ERR, "enter pam_sm_close_session\n");

    // identify user
    struct passwd *current_user = identify_user_pwd(pamh);
    if(!current_user)
        return PAM_SESSION_ERR;
    pam_syslog(pamh, LOG_ERR, "<<logout>> username: \"%s\", pwd: \"%s\", uid: %d\n", current_user->pw_name, current_user->pw_passwd, current_user->pw_uid);

    return PAM_SUCCESS;
}

COMMON_API PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if(flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;

    //for(int i=0; i<argc; i++)
    //    pam_syslog(pamh, LOG_ERR, "pam_sm_chauthtok arg %03d: %s\n", i, argv[i]);

    // identify user
    struct passwd *current_user = identify_user_pwd(pamh);
    if(!current_user)
        return PAM_SESSION_ERR;
    pam_syslog(pamh, LOG_ERR, "<<change pwd>> username: \"%s\", pwd: \"%s\", uid: %d\n", current_user->pw_name, current_user->pw_passwd, current_user->pw_uid);

    return PAM_SUCCESS;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ckm_notify");
#endif
