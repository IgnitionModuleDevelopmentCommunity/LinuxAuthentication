package org.imdc.authentication;

import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.licensing.LicenseState;
import com.inductiveautomation.ignition.gateway.model.AbstractGatewayModuleHook;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import org.imdc.authentication.linux.LinuxAuthType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GatewayHook extends AbstractGatewayModuleHook {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public void setup(GatewayContext gatewayContext) {
        BundleUtil.get().addBundle("LinuxAuthentication", LinuxAuthType.class, "LinuxAuthentication");

        try {
            gatewayContext.getUserSourceManager().addUserSourceProfileType(new LinuxAuthType());
        } catch (Exception ex) {
            logger.error("Error adding Linux authentication profile", ex);
        }
    }

    @Override
    public void startup(LicenseState licenseState) {

    }

    @Override
    public void shutdown() {

    }

    @Override
    public boolean isFreeModule() {
        return true;
    }
}
