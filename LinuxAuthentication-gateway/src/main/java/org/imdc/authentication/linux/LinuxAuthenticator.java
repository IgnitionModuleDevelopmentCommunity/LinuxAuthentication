package org.imdc.authentication.linux;

import com.google.common.base.Splitter;
import com.inductiveautomation.ignition.common.gui.UICallback;
import com.inductiveautomation.ignition.common.user.*;
import com.inductiveautomation.ignition.common.user.schedule.ScheduleAdjustment;
import com.inductiveautomation.ignition.gateway.authentication.impl.InternalUserSource;
import com.inductiveautomation.ignition.gateway.authentication.records.InternalUserRecord;
import com.inductiveautomation.ignition.gateway.localdb.persistence.PersistenceSession;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.user.UserSourceManager;
import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import simpleorm.dataset.SQuery;

import java.io.File;
import java.util.*;

/**
 * Created by travis.cox on 8/30/2017.
 */
public class LinuxAuthenticator extends InternalUserSource {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Splitter userInfoSplitter = Splitter.on(":");
    private final Splitter passwordSplitter = Splitter.on("$");

    private long profileId;
    private long cacheValidationTimeout;
    private String profileName;
    private GatewayContext context;
    private String usersFile;
    private List<String> exclusionList;
    private List<String> injectRoles;
    private Map<String, LinuxUser> cachedUsers;
    private Long lastCache;

    public LinuxAuthenticator(GatewayContext context, long profileId, final String profileName, long cacheValidationTimeout, final String usersFile, final String exclusionList, final String injectRoles) {
        super(context, profileId, profileName, cacheValidationTimeout);
        this.context = context;
        this.profileId = profileId;
        this.cacheValidationTimeout = cacheValidationTimeout;
        this.profileName = profileName;
        this.usersFile = usersFile;

        try {
            Splitter split = Splitter.on(",").trimResults().omitEmptyStrings();
            this.exclusionList = split.splitToList(exclusionList);
        } catch (Exception ex) {
            this.exclusionList = new ArrayList<String>();
            if (!(exclusionList == null || exclusionList.equals(""))) {
                logger.error("Error reading exclusion list. Verify the list is a comma separated list of user names.", ex);
            }
        }

        try {
            Splitter split = Splitter.on(",").trimResults().omitEmptyStrings();
            this.injectRoles = split.splitToList(injectRoles);
        } catch (Exception ex) {
            this.injectRoles = new ArrayList<String>();
            if (!(injectRoles == null || injectRoles.equals(""))) {
                logger.error("Error reading inject roles list. Verify the list is a comma separated list of roles.", ex);
            }
        }
    }

    @Override
    public long getProfileId() {
        return profileId;
    }

    @Override
    public String getName() {
        return profileName;
    }

    @Override
    public long getCacheValidationTimeout() {
        return cacheValidationTimeout;
    }

    @Override
    public AuthenticatedUser authenticate(AuthChallenge authChallenge) throws Exception {
        cacheUsers();

        String username = authChallenge.get(User.Username);
        String password = authChallenge.get(User.Password);

        logger.debug("Attempting to authenticate user '" + username + "'");

        if (!authChallenge.containsUsernameAndPassword()) {
            logger.warn("Authenticating using username and password is required");
            return null;
        }

        LinuxUser linuxUser = null;
        AuthenticatedUser user = null;

        if (cachedUsers != null) {
            linuxUser = cachedUsers.getOrDefault(username, null);
        }

        if (linuxUser == null) {
            logger.warn("Rejecting login for '" + username + "': not found.");
            return null;
        }
        PersistenceSession session = context.getPersistenceInterface().getSession();
        try {
            if (!linuxUser.isUserValid(password)) {
                return null;
            }

            InternalUserRecord userRec = findInternalUser(session, username);
            if (userRec == null) {
                user = new BasicAuthenticatedUser(profileName, username, username, injectRoles);
            } else {
                long userId = userRec.getUserId();
                List<String> roles = getRolesForUser(session, userRec);
                List<ContactInfo> contactInfo = getContactInfoForUser(session, userRec);
                List<ScheduleAdjustment> scheduleAdjustments = getScheduleAdjustmentsForUser(session, userRec);

                user = new BasicAuthenticatedUser(profileName, userId, username, roles)
                        .setContactInfo(contactInfo)
                        .setScheduleAdjustments(scheduleAdjustments);
                loadUserProperties(userRec, user);
                loadExtendedUserProperties(session, userRec, user);
            }
        } catch (Exception ex) {
            throw new Exception("Error while authenticating through Linux.", ex);
        } finally {
            session.rollback();
            session.close();
        }

        return user;
    }

    private void cacheUsers() {
        long currentTime = Calendar.getInstance().getTimeInMillis();
        if (lastCache == null || (currentTime - lastCache) > cacheValidationTimeout) {
            File f = new File(usersFile);
            List<String> lines = null;

            if (cachedUsers == null) {
                cachedUsers = new HashMap<String, LinuxUser>();
            }

            cachedUsers.clear();

            try {
                logger.debug("Reading '" + usersFile + "'");
                lines = FileUtils.readLines(f, "UTF-8");
                logger.debug("Found " + lines.size() + " users");

                for (String line : lines) {
                    try {
                        List<String> userInfo = userInfoSplitter.splitToList(line);
                        if (userInfo.size() >= 2) {
                            String username = userInfo.get(0);
                            String auth = userInfo.get(1);

                            if (username != null && !exclusionList.contains(username)) {
                                if (auth != null && auth.contains("$")) {
                                    List<String> authInfo = passwordSplitter.splitToList(auth);
                                    if (authInfo.size() >= 3) {
                                        String hashAlgorithm = authInfo.get(1);
                                        String salt = authInfo.get(2);

                                        if (hashAlgorithm != null && salt != null) {
                                            cachedUsers.put(username, new LinuxUser(auth, "$" + hashAlgorithm + "$" + salt));
                                        }
                                    }
                                }
                            } else {
                                logger.debug("User '" + username + "' found in exclusion list");
                            }
                        }
                    } catch (Exception ex) {
                        logger.debug("Error splitting '" + line + "'", ex);
                    }
                }
            } catch (Exception ex) {
                logger.error("Error reading password file", ex);
            }

            lastCache = Calendar.getInstance().getTimeInMillis();
        }
    }

    @Override
    public void startup(UserSourceManager userSourceManager) {

    }

    @Override
    public void shutdown() {

    }

    @Override
    public Collection<User> getUsers() {
        cacheUsers();

        Collection<User> internalUsers = super.getUsers();

        List<User> users = new ArrayList<User>();
        for (String username : cachedUsers.keySet()) {
            User user = null;

            for (User tmpUser : internalUsers) {
                if (tmpUser.get(User.Username).equals(username)) {
                    user = tmpUser;
                    break;
                }
            }

            if (user == null) {
                user = new BasicUser(profileName, username, injectRoles);
                user.set(User.Username, username);
            }

            users.add(user);
            logger.debug("Adding username '" + username + "'");
        }

        return users;
    }

    @Override
    protected List<String> getRolesForUser(PersistenceSession session, InternalUserRecord user) {
        List<String> roles = super.getRolesForUser(session, user);
        roles.addAll(injectRoles);
        return roles;
    }

    @Override
    public Set<UserSourceEditCapability> getEditFlags() {
        return EnumSet.of(UserSourceEditCapability.ADD_ROLE, UserSourceEditCapability.RENAME_ROLE, UserSourceEditCapability.DELETE_ROLE, UserSourceEditCapability.EDIT_USER_META);
    }

    @Override
    public void alterUser(User user, UICallback uiCallback) throws Exception {
        Long id = findUserInternalId(null, user);
        if (id == null) {
            super.addUser(user, uiCallback);
        } else {
            super.alterUser(user, uiCallback);
        }
    }

    @Override
    protected Long findUserInternalId(PersistenceSession session, User user) {
        boolean closeSession = false;
        if (session == null) {
            session = context.getPersistenceInterface().getSession();
            closeSession = true;
        }

        try {
            String username = user.get(User.Username);
            InternalUserRecord record = findInternalUser(session, username);
            return record == null ? null : record.getUserId();
        } finally {
            if (closeSession) {
                session.rollback();
                session.close();
            }
        }
    }

    private InternalUserRecord findInternalUser(PersistenceSession session, String uname) {
        SQuery<InternalUserRecord> findUser = new SQuery<InternalUserRecord>(InternalUserRecord.META)
                .eq(InternalUserRecord.ProfileId, profileId)
                .rawPredicate("lower(" + InternalUserRecord.Username.getFieldName() + ") = ?", uname.toLowerCase());

        List<InternalUserRecord> users = session.query(findUser);
        return users.size() > 0 ? users.get(0) : null;
    }

    private class LinuxUser {
        private String auth;
        private String salt;

        public LinuxUser(String auth, String salt) {
            this.auth = auth;
            this.salt = salt;
        }

        public boolean isUserValid(String pwd) throws Exception {
            logger.debug("Validating password '" + pwd + "'");
            logger.debug("Salt '" + salt + "'");
            logger.debug("Auth '" + auth + "'");
            String comparisonAuth = Crypt.crypt(pwd, salt);
            logger.debug("Comparison Auth '" + comparisonAuth + "'");
            return auth.equals(comparisonAuth);
        }
    }
}
