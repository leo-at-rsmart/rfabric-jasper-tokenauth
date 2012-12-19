package com.rsmart.rfabric.jasperreports.auth.kim;

import java.util.LinkedList;
import java.util.List;

import org.kuali.rice.kim.v2_0.*;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.message.Message;

import org.springframework.security.GrantedAuthority;

import com.rsmart.rfabric.jasperreports.auth.ExternalUserProvider;

import static com.rsmart.rfabric.logging.FormattedLogger.*;

public class KimUserProvider implements ExternalUserProvider {
    protected IdentityService_Service identityService;
    protected RoleService_Service roleService;
    protected PermissionService_Service permissionService;
    protected List<String> availableAuthorities;
    protected String endpointUrl;

    /**
     * Gets the value of endpointUrl
     *
     * @return the value of endpointUrl
     */
    public final String getEndpointUrl() {
        return this.endpointUrl;
    }

    /**
     * Sets the value of endpointUrl
     *
     * @param argEndpointUrl Value to assign to this.endpointUrl
     */
    public final void setEndpointUrl(final String argEndpointUrl) {
        this.endpointUrl = argEndpointUrl;
    }


    /**
     * Gets the value of availableAuthorities
     *
     * @return the value of availableAuthorities
     */
    public List<String> getAvailableAuthorities() {
        return this.availableAuthorities;
    }

    /**
     * Sets the value of availableAuthorities
     *
     * @param argAvailableAuthorities Value to assign to this.availableAuthorities
     */
    public void setAvailableAuthorities(final List<String> argAvailableAuthorities) {
        this.availableAuthorities = argAvailableAuthorities;
    }

    public boolean userExists(final String user) throws Exception {
        return getKimIdentityService().getPrincipalByPrincipalName(new GetPrincipalByPrincipalName() {{ setPrincipalName(user); }}) != null;
    }

    @SuppressWarnings("serial")
    public GrantedAuthority[] getAuthoritiesForUser(final String user) {
        final List<GrantedAuthority> authorities = new LinkedList<GrantedAuthority>();
        
        for (final String authorityName : availableAuthorities) {
            try {
                if (getKimPermissionService().hasPermission(user, "KR-SYS", authorityName)) {
                    authorities.add(new GrantedAuthority() {
                            
                            public int compareTo(Object o) {
                                GrantedAuthority that = (GrantedAuthority)o;
                                return getAuthority().compareTo(that.getAuthority());
                            }
                            
                            public String getAuthority() {
                                return authorityName;
                            }
                        });
                }
            }
            catch (Exception e) {
                warn("Unable to determine permissions for: %s: reason: %s", user, e.getMessage());
            }
        }
        final GrantedAuthority[] retval = new GrantedAuthority[authorities.size()];
        return authorities.toArray(retval);
    }

    public IdentityService getKimIdentityService() {
        return getIdentityService().getIdentityServicePort();
    }
        
    /**
     * Gets the value of identityService
     *
     * @return the value of identityService
     */
    public IdentityService_Service getIdentityService() {
        return this.identityService;
    }

    /**
     * Sets the value of identityService
     *
     * @param argIdentityService Value to assign to this.identityService
     */
    public void setIdentityService(final IdentityService_Service argIdentityService) {
        this.identityService = argIdentityService;

        final Client client = ClientProxy.getClient(getKimIdentityService());
        client.getRequestContext().put(Message.ENDPOINT_ADDRESS, getEndpointUrl()) ;        
    }

    public RoleService getKimRoleService() {
        return getRoleService().getRoleServicePort();
    }

    /**
     * Gets the value of roleService
     *
     * @return the value of roleService
     */
    public RoleService_Service getRoleService() {
        return this.roleService;
    }

    /**
     * Sets the value of roleService
     *
     * @param argRoleService Value to assign to this.roleService
     */
    public void setRoleService(final RoleService_Service argRoleService) {
        this.roleService = argRoleService;

        final Client client = ClientProxy.getClient(getKimRoleService());
        client.getRequestContext().put(Message.ENDPOINT_ADDRESS, getEndpointUrl()) ;        
    }

    
    public PermissionService getKimPermissionService() {
        return getPermissionService().getPermissionServicePort();
    }

    /**
     * Gets the value of permissionService
     *
     * @return the value of permissionService
     */
    public PermissionService_Service getPermissionService() {
        return this.permissionService;
    }

    /**
     * Sets the value of permissionService
     *
     * @param argPermissionService Value to assign to this.permissionService
     */
    public void setPermissionService(final PermissionService_Service argPermissionService) {
        this.permissionService = argPermissionService;

        final Client client = ClientProxy.getClient(getKimPermissionService());
        client.getRequestContext().put(Message.ENDPOINT_ADDRESS, getEndpointUrl()) ;        
    }
}
