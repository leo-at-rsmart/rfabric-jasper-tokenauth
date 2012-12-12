package com.rsmart.rfabric.jasperreports.auth.kim;

import org.kuali.rice.kim.v2_0.*;

import org.springframework.security.GrantedAuthority;

import com.rsmart.rfabric.jasperreports.auth.ExternalUserProvider;

public class KimUserProvider implements ExternalUserProvider {
    protected IdentityService_Service identityService;
    protected RoleService_Service roleService;
    protected PermissionService_Service permissionService;


    public boolean userExists(String user) {
        return getKimIdentityService().getPrincipalByPrincipalName(user) != null;
    }

    @SuppressWarnings("serial")
    public GrantedAuthority[] getAuthoritiesForUser(String user) {
        // TODO Determine what roles the user should have based upon roles in KIM
    
        // for now this is just a mock implementaiton that gives the user admin role
        GrantedAuthority[] mockAuthorities = new GrantedAuthority[1];
    
        mockAuthorities[0] = new GrantedAuthority() {

                public int compareTo(Object o) {
                    GrantedAuthority that = (GrantedAuthority)o;
                    return getAuthority().compareTo(that.getAuthority());
                }

                public String getAuthority() {
                    return "ROLE_ADMIN";
                }
      
            };
        return mockAuthorities;
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
    }
}
