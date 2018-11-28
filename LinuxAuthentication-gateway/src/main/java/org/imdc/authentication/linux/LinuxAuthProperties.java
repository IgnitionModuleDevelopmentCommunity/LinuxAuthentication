package org.imdc.authentication.linux;

import com.inductiveautomation.ignition.gateway.localdb.persistence.*;
import com.inductiveautomation.ignition.gateway.user.UserSourceProfileRecord;
import simpleorm.dataset.SFieldFlags;

/**
 * Created by travis.cox on 8/30/2017.
 */
public class LinuxAuthProperties extends PersistentRecord {

    public static final RecordMeta<LinuxAuthProperties> META = new RecordMeta<LinuxAuthProperties>(
            LinuxAuthProperties.class, "AuthProfileProperties_Linux");

    public static final LongField ProfileId = new LongField(META, "ProfileId", SFieldFlags.SPRIMARY_KEY);
    public static final ReferenceField<UserSourceProfileRecord> Profile = new ReferenceField<UserSourceProfileRecord>(
            META,
            UserSourceProfileRecord.META, "Profile", ProfileId);

    public static final StringField UsersFile = new StringField(META, "UsersFile").setWide().setDefault("/etc/shadow");
    public static final StringField ExclusionList = new StringField(META, "ExclusionList").setWide();
    public static final StringField InjectRoles = new StringField(META, "InjectRoles").setWide().setDefault("Administrator");

    static final Category LinuxCat = new Category("LinuxAuthentication.Category.Linux.Name", 1000)
            .include(UsersFile, ExclusionList, InjectRoles);

    static {
        ProfileId.getFormMeta().setVisible(false);
        Profile.getFormMeta().setVisible(false);

        UsersFile.getFormMeta().setFieldNameKey("LinuxAuthentication.UsersFile.Name");
        UsersFile.getFormMeta().setFieldDescriptionKey("LinuxAuthentication.UsersFile.Desc");
        ExclusionList.getFormMeta().setFieldNameKey("LinuxAuthentication.ExclusionList.Name");
        ExclusionList.getFormMeta().setFieldDescriptionKey("LinuxAuthentication.ExclusionList.Desc");
        InjectRoles.getFormMeta().setFieldNameKey("LinuxAuthentication.InjectRoles.Name");
        InjectRoles.getFormMeta().setFieldDescriptionKey("LinuxAuthentication.InjectRoles.Desc");
    }

    @Override
    public RecordMeta<LinuxAuthProperties> getMeta() {
        return META;
    }
}
