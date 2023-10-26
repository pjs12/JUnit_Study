package kr.co.ktds.aicentro.api.component.user.service;

import kr.co.ktds.aicentro.api.common.AccessReqStatus;
import kr.co.ktds.aicentro.api.common.SearchType;
import kr.co.ktds.aicentro.api.component.member.entity.Member;
import kr.co.ktds.aicentro.api.component.member.repository.MemberRepository;
import kr.co.ktds.aicentro.api.component.project.entity.ProjectId;
import kr.co.ktds.aicentro.api.component.user.entity.*;
import kr.co.ktds.aicentro.api.component.user.repository.*;
import kr.co.ktds.aicentro.api.config.ActivePropertiesConfig;
import kr.co.ktds.aicentro.common.constants.Role;
import kr.co.ktds.aicentro.common.event.EventAfterCommit;
import kr.co.ktds.aicentro.common.exception.AICentroBaseException;
import kr.co.ktds.aicentro.common.exception.DataNotFoundException;
import kr.co.ktds.aicentro.common.exception.DefaultAdminDeleteNotAllowException;
import kr.co.ktds.aicentro.common.repo.RepoService;
import kr.co.ktds.aicentro.common.repo.model.RepoUser;
import kr.co.ktds.aicentro.common.service.StorageAccessKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@Slf4j
@RunWith(SpringRunner.class)
public class UserServiceTest {

    @InjectMocks
    private UserService userService;

    @Mock
    private EmployeeRepository employeeRepository;

    @Mock
    private DepartmentRepository departmentRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private AccessReqHistRepository accessReqHistRepository;

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private QueryoneRepository queryoneRepository;

    @Mock
    private RepoService repoService;

    @Mock
    private ApplicationEventPublisher publisher;

    @Mock
    ActivePropertiesConfig activeConfig;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Value("${aicentro.sso.default-admin}")
    private String defaultAdmin;

    @Test
    public void selectEmployee() {
        // Given
        String empno = "12345";
        String orgCd = "testOrgCd";

        Employee employee = Employee.builder()
                .empNo(empno)
                .orgCd(orgCd)
                .build();

        Department department = Department.builder()
                .orgCd(employee.getOrgCd())
                .build();

        when(employeeRepository.findById(empno)).thenReturn(Optional.of(employee));
        when(departmentRepository.findById(employee.getOrgCd())).thenReturn(Optional.of(department));

        // When
        EmployeeDto.ResponseDetail response = userService.selectEmployee(empno);

        // Then
        verify(employeeRepository, times(1)).findById(empno);
        verify(departmentRepository, times(1)).findById(employee.getOrgCd());
        assertNotNull(response);
        assertEquals(empno, response.getEmpNo());
        assertEquals(department.getOrgCd(), response.getOrgCd());
    }

    @Test(expected = DataNotFoundException.class)
    public void selectEmployee_NotFoundException() {
        // Given
        String empno = "4567";
        when(employeeRepository.findById(empno)).thenReturn(Optional.empty());

        // When
        userService.selectEmployee(empno);

        // Then
    }

    @Test
    public void create() {
        // Given
        String userId = "testUser";
        String password = "testPassword";
        String name = "testName";
        String email = "test@email.com";
        int repoUid = 10;
        String token = "TestTokenn";
        Date date = new Date();

        UserDto.Create userDto = UserDto.Create.builder()
                .userId(userId)
                .password(password)
                .name(name)
                .email(email)
                .build();

        AccessReqHistDto.Create create = AccessReqHistDto.Create.builder()
                .userId(userId)
                .status(AccessReqStatus.CREATED)
                .build();

        UserExtra extra = UserExtra.builder()
                .enableGit(true)
                .storageAccessKey(StorageAccessKey.EMPTY())
                .sharedDiskPath(name)
                .repoUid(repoUid)
                .repoToken(token)
                .build();

        User user = userDto.toEntity(passwordEncoder, date);
        user.updateUserExtra(extra);

        RepoUser repoUser = new RepoUser() {};
        repoUser.setRepoUid(repoUid);
        repoUser.setRepoToken(token);

        when(activeConfig.isRepo()).thenReturn(true);
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(accessReqHistRepository.save(any(AccessReqHist.class))).thenReturn(create.toEntity());
        when(repoService.createUser(anyString(), anyString(), anyString(), anyString(), anyLong())).thenReturn(repoUser);

//        String propertyValue = environment.getProperty("aicentro.repo.type");
//        log.debug("=================== property = {}", propertyValue);

        // When
        User createUser = userService.create(userDto, AccessReqStatus.APPROVAL);

        // Then
        assertEquals(userId, createUser.getUserId());
        assertEquals(user, createUser);
    }

    @Test
    public void selectUserList() {
        // Given
        AccessReqStatus status = AccessReqStatus.ALL;
        String roleType = "testRoleType";
        Date from = new Date();
        Date to = new Date();
        SearchType searchType = SearchType.ALL;
        String keyword = "testKeyword";
        String enabled = "Y";
        Pageable pageable = Pageable.unpaged();

        UserDto.Response response1 = UserDto.Response.builder()
                .id(10L)
                .userId("testUserId1")
                .email("testEmail1")
                .build();
        UserDto.Response response2 = UserDto.Response.builder()
                .id(20L)
                .userId("testUserId2")
                .email("testEmail2")
                .build();

        List<UserDto.Response> responseList = new ArrayList<>();
        responseList.add(response1);
        responseList.add(response2);

        Page<UserDto.Response> testResult = new PageImpl<>(responseList);

        when(userRepository.findAllBySearchParamAsUserDtoResponse(
                any(AccessReqStatus.class), any(String.class), any(Date.class), any(Date.class), any(SearchType.class), any(String.class), any(String.class), any(Pageable.class)
        )).thenReturn(testResult);

        // When
        Page<UserDto.Response> result = userService.selectUserList(status, roleType, from, to, searchType, keyword, enabled, pageable);

        // Then
        assertEquals(testResult, result);
    }

    @Test
    public void selectUserListAdmin() {
        // Given
        User user1 = User.builder()
                .name("testName111")
                .hngBrNm("testHngBrNm111")
                .roles("testRoles111")
                .build();
        User user2 = User.builder()
                .name("testName222")
                .hngBrNm("testHngBrNm222")
                .roles("testRoles222")
                .build();

        UserDto.ListAdmin admin1 = new UserDto.ListAdmin(user1);
        UserDto.ListAdmin admin2 = new UserDto.ListAdmin(user2);

        List<UserDto.ListAdmin> testAdminList = new ArrayList<>();
        testAdminList.add(admin1);
        testAdminList.add(admin2);

        when(userRepository.findAllByAdminDtoResponse()).thenReturn(testAdminList);

        // When
        List<UserDto.ListAdmin> resultAdminList = userService.selectUserListAdmin();

        // Then
        assertEquals(testAdminList, resultAdminList);
    }

    @Test
    public void selectUserListForSearch() {
        // Given
        SearchType searchType = SearchType.CONTENT;
        String keyword = "test";
        String projectId = "project123";
        String serviceId = "456";
        Pageable pageable = Pageable.unpaged();

        UserDto.ResponseSearch search1 = UserDto.ResponseSearch.builder()
                .userId("testUserId111")
                .name("testName111")
                .orgNm("testOrgNm111")
                .build();

        UserDto.ResponseSearch search2 = UserDto.ResponseSearch.builder()
                .userId("testUserId222")
                .name("testName222")
                .orgNm("testOrgNm222")
                .build();

        List<UserDto.ResponseSearch> testList = new ArrayList<>();
        testList.add(search1);
        testList.add(search2);

        Page<UserDto.ResponseSearch> testPage = new PageImpl<>(testList);

        when(userRepository.findAllEnabledBySearchParams(
                searchType, keyword, new ProjectId(projectId), Long.parseLong(serviceId), pageable
        )).thenReturn(testPage);

        // When
        Page<UserDto.ResponseSearch> resultPage = userService.selectUserListForSearch(searchType, keyword, projectId, serviceId, pageable);

        // Then
        assertEquals(testPage, resultPage);
    }

    @Test
    public void checkUserByUserId_Existing() throws DataNotFoundException {
        // Given
        String userId = "testUserId";
        User user = User.builder()
                .userId(userId)
                .build();
        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));

        // When
        Boolean result = userService.checkUserByUserId(userId);

        // Then
        assertTrue(result);
    }

    @Test
    public void checkUserByUserId_NonExisting() throws DataNotFoundException {
        // Given
        String userId = "testUserId";
        when(userRepository.findByUserId(userId)).thenReturn(Optional.empty());

        // When
        Boolean result = userService.checkUserByUserId(userId);

        // Then
        assertFalse(result);
    }

    @Test
    public void findByUserId_Existing() {
        // Given
        String userId = "userId";
        User user = User.builder()
                .userId(userId)
                .build();

        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));

        // When
        User result = userService.findByUserId(userId);

        // Then
        assertNotNull(result);
        assertEquals(user, result);
    }

    @Test(expected = DataNotFoundException.class)
    public void findByUserId_NonExisting() {
        // Given
        String userId = "userId";
        when(userRepository.findByUserId(userId)).thenReturn(Optional.empty());

        // When
        userService.findByUserId(userId);

        // Then
    }

    @Test
    public void checkAccessReqHistByUserId_Existing() throws DataNotFoundException {
        // Given
        String userId = "userId";
        AccessReqHist accessReqHist = AccessReqHist.builder()
                .userId(userId)
                .build();

        when(accessReqHistRepository.findByUserId(userId)).thenReturn(Optional.of(accessReqHist));

        // When
        Boolean result = userService.checkAccessReqHistByUserId(userId);

        // Then
        assertTrue(result);
    }

    @Test
    public void checkAccessReqHistByUserId_NonExisting() throws DataNotFoundException {
        // Given
        String userId = "userId";
        when(accessReqHistRepository.findByUserId(userId)).thenReturn(Optional.empty());

        // When
        Boolean result = userService.checkAccessReqHistByUserId(userId);

        // Then
        assertFalse(result);
    }

    @Test
    public void selectUser_Existing() throws DataNotFoundException {
        // Given
        long id = 5L;
        UserDto.ResponseDetail responseDetail = UserDto.ResponseDetail.builder()
                .id(id)
                .isAdmin(false)
                .build();

        when(userRepository.findByIdAsDtoResponse(id)).thenReturn(responseDetail);

        // When
        UserDto.ResponseDetail result = userService.selectUser(id);

        // Then
        assertEquals(responseDetail, result);
    }

    @Test(expected = DataNotFoundException.class)
    public void selectUser_NonExisting() throws DataNotFoundException {
        // Given
        long id = 10L;
        when(userRepository.findByIdAsDtoResponse(id)).thenReturn(null);

        // When
        userService.selectUser(id);

        // Then
    }

    @Test
    public void selectAccessReqHist_Existing() throws DataNotFoundException {
        // Given
        String userId = "userId";
        AccessReqHist accessReqHist = AccessReqHist.builder()
                .userId(userId)
                .build();

        when(accessReqHistRepository.findByUserId(userId)).thenReturn(Optional.of(accessReqHist));

        // When
        AccessReqHist result = userService.selectAccessReqHist(userId);

        // Then
        assertNotNull(result);
        assertEquals(accessReqHist, result);
    }

    @Test
    public void selectAccessReqHist_NonExisting() throws DataNotFoundException {
        // Given
        String userId = "userId";
        User user = User.builder()
                .userId(userId)
                .build();
        AccessReqHist accessReqHist = AccessReqHist.builder()
                .userId(userId)
                .build();

        when(accessReqHistRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));
        when(accessReqHistRepository.save(accessReqHist)).thenReturn(accessReqHist);

        // When
        AccessReqHist result = userService.selectAccessReqHist(userId);

        // Then
        assertNotNull(result);
        assertEquals(accessReqHist.getUserId(), result.getUserId());
    }

    @Test
    public void changeUserAccessReqStatus_Existing() {
        // Given
        String userId = "TestUserId111";
        AccessReqHistDto.Update update = AccessReqHistDto.Update.builder()
                .id(4L)
                .userId(userId)
                .status(AccessReqStatus.APPROVAL)
                .build();

        AccessReqHist accessReqHist = AccessReqHist.builder()
                .userId(userId)
                .build();

        UserExtra extra = UserExtra.builder()
                .sharedDiskPath("sharedDiskPath")
                .storageAccessKey(StorageAccessKey.EMPTY())
                .build();

        User user = User.builder()
                .userId(userId)
                .userExtra(extra)
                .build();
        user.setEnabled(userId);

        UserDto.ResponseDetail responseDetail = UserDto.ResponseDetail.builder()
                .userId(userId)
                .isAdmin(false)
                .build();

        Member member = Member.builder().build();

        when(accessReqHistRepository.findById(update.getId())).thenReturn(Optional.of(accessReqHist));
        when(userRepository.findByUserId(accessReqHist.getUserId())).thenReturn(Optional.of(user));
        when(memberRepository.findById(accessReqHist.getUserId())).thenReturn(Optional.empty());
        when(userRepository.findByUserIdAsDtoResponse(accessReqHist.getUserId())).thenReturn(responseDetail);
        when(memberRepository.save(any(Member.class))).thenReturn(member);

        // When
        AccessReqHistDto.ResponseDetail result = userService.changeUserAccessReqStatus(update, userId);

        // Then
        verify(memberRepository).save(any(Member.class));
        verify(publisher).publishEvent(any(EventAfterCommit.class));
//        verify(notificationService).sendMessage(any(String.class), any(NotificationFormatType.class), any(NotificationParam.class), any(NotificationDeliveryType.class));
        assertNotNull(result);
        assertEquals(accessReqHist.getUserId(), result.getUserId());
    }

    @Test(expected = DataNotFoundException.class)
    public void changeUserAccessReqStatus_NonExisting() {
        // Given
        String userId = "TestUserId111";
        AccessReqHistDto.Update update = AccessReqHistDto.Update.builder()
                .id(4L)
                .userId(userId)
                .status(AccessReqStatus.APPROVAL)
                .build();

        when(accessReqHistRepository.findByUserId(update.getUserId())).thenReturn(Optional.empty());

        // When
        userService.changeUserAccessReqStatus(update, userId);

        // Then
    }

    @Test
    public void changeUserRole_Existing() {
        // Given
        String userId = "userId";
        long id = 1L;
        UserDto.UpdateRole userDto = UserDto.UpdateRole.builder()
                .id(id)
                .role(Arrays.asList("testRole1", "testRole2"))
                .build();

        User user = User.builder()
                .id(id)
                .userId(userId)
                .build();
        user.changeRoles(userDto.getRole(), userId);

        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        // When
        UserDto.ResponseDetail result = userService.changeUserRole(userDto, userId);

        // Then
        assertNotNull(result);
        assertEquals(userId, result.getUserId());
        assertEquals(userDto.getRole(), result.getRole());
    }

    @Test(expected = DataNotFoundException.class)
    public void changeUserRole_NonExisting() {
        // Given
        long id = 3L;
        UserDto.UpdateRole userDto = UserDto.UpdateRole.builder()
                .id(id)
                .role(Arrays.asList("testRole33", "testRole444"))
                .build();

        when(userRepository.findById(id)).thenReturn(Optional.empty());

        // When
        userService.changeUserRole(userDto, any(String.class));

        // Then
    }

    @Test
    public void deleteUser() throws Exception {
        // Given
        String userId = "deleteUser";
        User user = User.builder()
                .userId(userId)
                .build();

        AccessReqHist accessReqHist = AccessReqHist.builder()
                .userId(userId)
                .status(AccessReqStatus.CREATED)
                .build();

        Member member = Member.builder()
                .userId(defaultAdmin)
                .build();

        UserDto.Delete delete = UserDto.Delete.of(user);

        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));
        when(accessReqHistRepository.findByUserId(userId)).thenReturn(Optional.of(accessReqHist));
        when(activeConfig.isRepo()).thenReturn(true);

        // When
        UserDto.Delete result = userService.deleteUser(userId);

        // Then
        assertEquals(delete, result);
        assertEquals(userId, result.getUserId());
        verify(publisher).publishEvent(any(EventAfterCommit.class));
        verify(accessReqHistRepository).delete(accessReqHist);
        verify(userRepository).delete(user);
        verify(repoService).deleteUser(any(String.class));
    }

    @Test(expected = DefaultAdminDeleteNotAllowException.class)
    public void deleteUser_defaultAdmin() throws Exception {
        // Given
        String defaultAdmin = "aicentro";

        // When
        userService.deleteUser(defaultAdmin);

        // Then
    }

    @Test(expected = DataNotFoundException.class)
    public void deleteUser_NonExisting() throws Exception {
        // Given
        String userId = "deleteUserId";
        when(userRepository.findByUserId(userId)).thenReturn(Optional.empty());

        // When
        userService.deleteUser(userId);

        // Then
    }

    @Test
    public void countAllByEnabled() throws ParseException {
        // Given
        Map<Boolean, Long> counts = new HashMap<>();
        counts.put(true, 10L);
        counts.put(false, 20L);

        long updatedCount = 5L;

        UserDto.ResponseCount reponseCount = UserDto.ResponseCount.empty();
        counts.forEach(reponseCount::updateValue);
        reponseCount.updateUpdatedValue(updatedCount);

        when(userRepository.countAllByEnabled()).thenReturn(counts);
        when(userRepository.countByUpdatedAtBetween(any(Date.class), any(Date.class))).thenReturn(updatedCount);

        // When
        UserDto.ResponseCount result = userService.countAllByEnabled();

        // Then
        assertEquals(reponseCount, result);
        assertEquals(10L, result.getTotal());
        assertEquals(20L, result.getCreated());
        assertEquals(5L, result.getUpdated());
    }

    @Test
    public void findSystemAdmin() {
        // Given
        String defaultAdmin = "defaultAdmin";
        Member member = Member.builder()
                .userId(defaultAdmin)
                .build();

        when(memberRepository.findOneByUserId(defaultAdmin)).thenReturn(Optional.of(member));

        // When
        Member result = userService.findSystemAdmin();

        // Then
        assertEquals(member, result);
    }

    @Test(expected = AICentroBaseException.class)
    public void findSystemAdmin_Exception() {
        // Given
        String defaultAdmin = "defaultAdmin";

        when(memberRepository.findOneByUserId(defaultAdmin)).thenReturn(Optional.empty());

        // When
        userService.findSystemAdmin();

        // Then
    }

//    @Test
//    public void deleteMemberInAllProject() {
//        // Given
//        String memberId = "deleteMemberId";
//        List<ProjectMemberDto.ResponseProject> projectList = new ArrayList<>();
//        ProjectMemberDto.ResponseProject response1 = ProjectMemberDto.ResponseProject.builder()
//                .userId("userId")
//                .projectId("project111")
//                .build();
//        ProjectMemberDto.ResponseProject response2 = ProjectMemberDto.ResponseProject.builder()
//                .userId("userId")
//                .projectId("project222")
//                .build();
//
//        projectList.add(response1);
//        projectList.add(response2);
//
//        Page<ProjectMemberDto.ResponseProject> pageList = new PageImpl<>(projectList);
//
//        when(projectMemberService.selectProjectListByMemberId(memberId, any(PageRequest.class))).thenReturn(pageList);
//        doNothing().when(projectMemberService.deleteProjectMember(any(String.class), any(Long.class), any(Member.class)));
//
//        // When
//        userService.deleteMemberInAllProject(memberId);
//
//        // Then
//        verify(projectMemberService, times(1)).selectProjectListByMemberId(memberId, any(PageRequest.class));
//        verify(projectMemberService, times(projectList.size())).deleteProjectMember(anyString(), anyLong(), any(Member.class));
//    }

    @Test
    public void getRoleUserList() {
        // Given
        Role role1 = Role.ROLE_ADMIN;
        Role role2 = Role.ROLE_AUDIT_ADMIN;

        List<Role> roleList = Arrays.asList(role1, role2);

        User user1 = User.builder()
                .userId("userId11")
                .enabled(true)
                .roles(role1.getSecurityRole())
                .build();

        User user2 = User.builder()
                .userId("userId222")
                .enabled(true)
                .roles(role2.getSecurityRole())
                .build();

        List<User> userList = Stream.of(user1, user2).collect(Collectors.toList());

        when(userRepository.findAllByRolesInAndEnabled(anyList(), eq(true))).thenReturn(userList);

        // When
        List<User> result = userService.getRoleUserList(roleList);

        // Then
        assertEquals(userList, result);
    }

    @Test
    public void removeRetirementUsers() throws IOException {
        // Given
        Member member = Member.builder()
                .userId(defaultAdmin)
                .build();

        User user1 = User.builder()
                .userId("userId111")
                .build();
        User user2 = User.builder()
                .userId("userId222")
                .build();

        List<User> userList = Stream.of(user1, user2).collect(Collectors.toList());

        when(userRepository.findAllByRetirementUser(eq(member))).thenReturn(userList);

        // When
        userService.removeRetirementUsers();

        // Then
        verify(userRepository, times(1)).findAllByRetirementUser(eq(member));
        verify(userRepository, times(userList.size())).delete(any(User.class));
        verify(userService, times(1)).batchDeleteUsers();
    }

    @Test
    public void getVerticaUser() {
        // Given
        User user1 = User.builder()
                .userId("userId11111")
                .build();
        User user2 = User.builder()
                .userId("userId22222")
                .build();

        List<User> userList = Stream.of(user1, user2).collect(Collectors.toList());

        when(userRepository.findVerticaApplyUser()).thenReturn(userList);

        // When
        List<User> result = userService.getVerticaUser();

        // Then
        assertEquals(userList, result);
    }

    @Test
    public void updateVerticaUser() {
        // Given
        User user1 = User.builder()
                .userId("updateVerticaUser_userId11111")
                .build();
        User user2 = User.builder()
                .userId("updateVerticaUser_userId22222")
                .build();

        List<User> allUser = Stream.of(user1, user2).collect(Collectors.toList());

        when(userRepository.findAll()).thenReturn(allUser);
        when(userRepository.save(any(User.class))).thenReturn(user1);

        // When
        boolean result = userService.updateVerticaUser();

        // Then
        verify(userRepository, times(allUser.size())).save(any(User.class));
        assertTrue(result);
    }

    @Test
    public void getDbAuthList() {
        // Given
        String userId = "getDbAuthList_userId";
        Queryone queryone1 = Queryone.builder()
                .empNo(userId)
                .user_name("userName11111")
                .build();
        Queryone queryone2 = Queryone.builder()
                .empNo(userId)
                .user_name("userName22222")
                .build();

        List<Queryone> queryList = Stream.of(queryone1, queryone2).collect(Collectors.toList());

        User user = User.builder()
                .userId(userId)
                .secretEnable(true)
                .build();

        List<QueryoneDto.Response> responseList = queryList.stream()
                        .map(one ->
                            QueryoneDto.Response.builder()
                                    .id(one.getId())
                                    .db_account_id(one.getDb_account_id())
                                    .empNo(one.getEmpNo())
                                    .build()
                        )
                        .collect(Collectors.toList());

        when(queryoneRepository.findByEmpNo(userId)).thenReturn(queryList);
        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));

        // When
        List<QueryoneDto.Response> result = userService.getDbAuthList(userId);

        // Then
        assertEquals("userName11111", queryList.get(0).getUser_name());
        assertEquals(userId, user.getUserId());
        assertEquals(responseList, result);
    }

    @Test
    public void updateUser() {
        // Given
        String userId = "updateUserId";
        UserDto.Modify userDto = UserDto.Modify.builder()
                .role(Stream.of("ROLE_TEST").collect(Collectors.toList()))
                .enabled(true)
                .build();
        userDto.setUserId(userId);

        User user = User.builder()
                .userId(userId)
                .enabled(true)
                .build();

        when(userRepository.findByUserId(userId)).thenReturn(Optional.of(user));

        // When
        UserDto.ResponseDetail result = userService.updateUser(userDto);

        // Then
        assertEquals(userId, result.getUserId());
        assertTrue(result.isEnabled());
    }

    @Test
    public void getUserAuthority() throws DataNotFoundException {
        // Given
        String userId = "getAuthorityUserId";
        String role = "ROLE_TEST_ADMIN";
        User user = User.builder()
                .userId(userId)
                .roles(role)
                .build();

        Map<String, Object> testMap = new HashMap<>();
        testMap.put("user_id", userId);
        testMap.put("role", Stream.of(role).collect(Collectors.toList()));

        when(userRepository.findOneByUserId(userId)).thenReturn(user);

        // When
        Map<String, Object> result = userService.getUserAuthority(userId);

        // Then
        assertEquals(testMap, result);
        assertEquals(userId, result.get("user_id"));
    }

    @Test(expected = DataNotFoundException.class)
    public void getUserAuthority_NotFound() throws DataNotFoundException {
        // Given
        String userId = "getAuthorityUserId";

        when(userRepository.findOneByUserId(userId)).thenReturn(null);

        // When
        userService.getUserAuthority(userId);

        // Then
    }

    @Test
    public void getTokenSecret() throws DataNotFoundException {
        // Given
        String userId = "getTokenUserId";
        String secret = "getTokenSecret";
        UserExtra extra = UserExtra.builder()
                .storageAccessKey(StorageAccessKey.builder().secret(secret).build())
                .build();
        User user = User.builder()
                .userId(userId)
                .userExtra(extra)
                .build();

        Map<String, Object> testMap = new HashMap<>();
        testMap.put("user_id", userId);
        testMap.put("token_secret", secret);

        when(userRepository.findOneByUserId(userId)).thenReturn(user);

        // When
        Map<String, Object> result = userService.getTokenSecret(userId);

        // Then
        assertEquals(testMap, result);
        assertEquals(userId, result.get("user_id"));
        assertEquals(secret, result.get("token_secret"));
    }

    @Test(expected = DataNotFoundException.class)
    public void getTokenSecret_NotFound() throws DataNotFoundException {
        // Given
        String userId = "getTokenUserId";

        when(userRepository.findOneByUserId(userId)).thenReturn(null);

        // When
        userService.getTokenSecret(userId);

        // Then
    }

}
