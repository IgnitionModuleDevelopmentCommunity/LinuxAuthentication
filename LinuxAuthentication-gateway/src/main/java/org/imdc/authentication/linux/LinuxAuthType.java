package org.imdc.authentication.linux;

import com.inductiveautomation.ignition.gateway.localdb.persistence.PersistentRecord;
import com.inductiveautomation.ignition.gateway.localdb.persistence.RecordMeta;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.user.UserSourceProfile;
import com.inductiveautomation.ignition.gateway.user.UserSourceProfileRecord;
import com.inductiveautomation.ignition.gateway.user.UserSourceProfileType;

/**
 * Created by travis.cox on 8/30/2017.
 */
public class LinuxAuthType extends UserSourceProfileType {

    public static final String EXTENSION_POINT_TYPE = "LINUX";

    public LinuxAuthType() {
        super(EXTENSION_POINT_TYPE, "LinuxAuthentication.Name", "LinuxAuthentication.Description");
    }

    @Override
    public UserSourceProfile createNewProfile(UserSourceProfileRecord userSourceProfileRecord, GatewayContext gatewayContext) throws Exception {
        LinuxAuthProperties props = gatewayContext.getPersistenceInterface().find(LinuxAuthProperties.META, userSourceProfileRecord.getId());
        if (props == null) {
            throw new NullPointerException("No properties found for authentication profile: " + userSourceProfileRecord.getName());
        }

        LinuxAuthenticator profile = new LinuxAuthenticator(gatewayContext, userSourceProfileRecord.getId(), userSourceProfileRecord.getName(), userSourceProfileRecord.getCacheValidationTimeout(), props.getString(props.UsersFile), props.getString(props.ExclusionList), props.getString(props.InjectRoles));
        return profile;
    }

    @Override
    public RecordMeta<? extends PersistentRecord> getSettingsRecordType() {
        return LinuxAuthProperties.META;
    }
}
