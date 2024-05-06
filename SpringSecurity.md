![ss](images/ss.jpg)

# 一、前置知识

- Java web基本体系
- Spring + SpringMVC + MyBatis  + SpringBoot框架体系
- RBAC 相关知识点
- Redis 基本操作



# 二、教程目标

- 了解权限管理系统
- Spring Security 框架基本操作
- JWT 令牌认证
- Spring Security 项目实战



# 三、框架简介

Spring 是非常流行和成功的 Java 应用开发框架，Spring Security 正是 Spring 家族中的成员。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。

而应用安全方面的两个核心功能为：**用户认证（Authentication）和用户授权（Authorization）**，这两点也是 Spring Security 重要核心功能。

- 用户认证指的是：验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。用户认证一般要求用户提供用户名和密码，系统通过校验用户名和密码来完成认证过程。

  **大白话：系统认为用户是否能登录**

- 用户授权指的是：验证某个用户是否有权限执行某个操作。在一个系统中，不同用户所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限。

  **大白话：系统判断用户是否有权限去做某些事情。**
  
  

![89c5561781f0c0da4a297b52bcec1028](images/89c5561781f0c0da4a297b52bcec1028.jpeg)





# 四、竞品对比

## 4.1 Spring Security

Spring Security 也是目前较为流行的一个安全权限管理框架，它与 Spring 紧密结合在一起。

**特点：**

- 和 Spring 无缝整合

- 全面的权限控制

- 专门为 Web 开发而设计
- 重量级

## 4.2 Shiro

Apache Shiro 是一个强大且易用的 Java 安全框架，它可实现身份验证、授权、密码和会话管理等功能。

**特点：**

- 轻量级。Shiro 主张的理念是把复杂的事情变简单。针对对性能有更高要求的互联网应用有更好表现。

- 通用性。不局限于 Web 环境，可以脱离 Web 环境使用；在 Web 环境下一些特定的需求需要手动编写代码定制。

## 4.3 Spring Security VS Shiro 

在SpringBoot出来之前，传统SSM框架集成Spring Security相对麻烦，市场占有率一直低于Shiro，自 Spring Boot 之后，SpringBoot 对于 Spring Security 提供了自动化配置方案，可以使用更少的配置来使用 Spring Security，市场占有率逐步提升。

目前来说：常见的安全管理技术栈的组合是这样的：

• SSM + Shiro

• Spring Boot/Spring Cloud + Spring Security



# 五、入门案例

## 5.1 版本说明

官方文档：

中文：

6版本：https://springdoc.cn/spring-security/

5版本：https://www.docs4dev.com/docs/zh/spring-security/5.1.2.RELEASE/reference/

英文：

6版本：https://docs.spring.io/spring-security/reference/index.html

注意：

SpringBoot2.x版本支持的是SpringSecurity 5.x  

SpringBoot3.x版本支持的是SpringSecurity 6.x  



**SpringSecurity5.x 与 SpringSecurity6.x 功能一样，用法几乎一致**，区别是授权模块，SpringSecuriy6.x底层作了很大改动，部分类被放弃。

**本教程使用SpringBoot2.x 版本，对应的是SpringSecurity 5.x，新版本控的同学可以按照个人爱好选择。**

## 5.2 代码实现

**步骤2：导入依赖**

```xml
<!-- SpringBoot的依赖配置-->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.2.2.RELEASE</version>
    <relativePath/> <!-- lookup parent from repository -->
</parent>
<dependenc boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
    </dependency>

    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>
</dependencies>
```

**步骤3：创建 application.properties**

**步骤4：创建启动类**

```java
@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class,args);
    }
}

```

**步骤5：创建controller**

```java
@RestController
public class HelloController {
    @RequestMapping("/hello")
    public String hello(String name){
        return "操作成功";
    }
}
```

**步骤6：启动并访问**

在浏览器访问资源: http://localhost:8080/hello, 会发现访问资源被拦截了,spring Security默认提供认证页面，不需要额外开发。 

![image-20221102162327871](images/image-20221102162327871.png)

观察控制台会生成一个密码，默认账号是 user

```java
Using generated security password: a6c875c9-9b2e-4df9-a517-56c571258b01
```



# 六、案例分析

## 6.1 Web组件

不管是单体结构项目，还是分布式/微服务项目，只要还是Web项目，都会遵循一个主干线：**发起请求-接收请求-处理请求-响应请求**，只要这个主干线不变，下面的Web组件工作流程也不会变。

![image-20240122112039959](images/image-20240122112039959.png)

上面的Web组件操作流程，需要记忆，属于Web操作灵魂，后面不管是SpringMVC还是其他Web框架，都是可以立即为灵魂之上的肉体。记住：**好看的皮囊千篇一律，有趣的灵魂万里挑一**

## 6.2 案例分析

来看下上面hello world 案例，基本流程如下

![image-20240122164308913](images/image-20240122164308913.png)



# 七、认证定制

自带的登录认证与登录拦截还是存在很多不方便，开发中一般不使用默认认证，往往需要根据项目定制。

## 7.1 登录用户定制

默认情况下，用户设置为user，密码随机。如果不想这么麻烦，可以自己居于内存或者居于数据库2种方式定制。

### 7.1.1 居于内存

项目中很少使用这种方式，更多是单元测试时使用，因为数据是存放在内存中。

**步骤1：创建Spring Security 配置类**

```java
@Configuration
public class SpringSecurityConfig {
    
}
```

**步骤2：配置本地用户信息获取服务**

```java
@Configuration
public class SpringSecurityConfig {
    //配置用户信息服务
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("dafei").password("666").authorities("p1").build());
        manager.createUser(User.withUsername("xiaofei").password("888").authorities("p2").build());
        return manager;
    }
}
```

API解释：

- UserDetailsService：用户信息服务接口，是Spring Security 用户操作接口
- InMemoryUserDetailsManager：用户信息管理器，用于管理用户列表。加载用户信息会缓存在内存中。
- UserDetails：用户信息接口，是Spring Security  提供默认用户信息封装接口，里面定制用户操作各种规范方法
- User：是UserDetails实现类，开发者可以更加项目需求定制。

**步骤3：配置密码加密器**

```java
@Configuration
public class SpringSecurityConfig {
    //配置用户信息服务
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("dafei").password("666").authorities("p1").build());
        manager.createUser(User.withUsername("xiaofei").password("888").authorities("p2").build());
        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
```

API解释：

- PasswordEncoder：密码加密器
- NoOpPasswordEncoder：空密码加密器，也就是密码不加密

**步骤4：启动测试**

*![image-20240122173509829](images/image-20240122173509829.png)*



### 7.1.2 居于数据库

所谓居于数据库，这个就简单了，就是去查数据库用户表，加载用户信息。

此处暂时不讲，等后面改造RBAC时候再说。



## 7.2 登录页面定制

开发中，项目都有自己的登录页面，用不上默认的登录页面，这时就需要自个定制了。这里要注意，一但定制后，原先的页面、默认自动认证都会失效，都需要从新定制。

**步骤1：定制登录页面**

/resources/static/login.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org/" lang="en">
<head>
  <meta charset="UTF-8">
  <title>用户登录</title>
</head>
<body>
<h1>用户登录</h1>
<form action="/login" method="post">
  用户名：<input type="text" name="username"> <br>
  密码：<input type="text" name="password"><br>
  <input type="submit" value="登录">
</form>
</body>
</html>

```

**步骤2：修改SpringSecurityConfig**

继承WebSecurityConfigurerAdapter，重写configure(HttpSecurity http)

```java
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    //配置用户信息服务-本地
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("dafei").password("666").authorities("p1").build());
        manager.createUser(User.withUsername("xiaofei").password("888").authorities("p2").build());
        return manager;
    }

    //密码加密器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    //自定义配置
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //禁用csrf保护
        http.csrf().disable();

        //请求url权限控制
        http.authorizeRequests()
                .antMatchers("/login.html").permitAll()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated();

        //用户登录控制
        http.formLogin()
                .loginProcessingUrl("/login")
                .loginPage("/login.html");
    }
}
```

**API解释**

- http.csrf().disable() ：禁用csrf保护

  Spring security为防止CSRF（Cross-site request forgery跨站请求伪造）的发生，限制了除了get以外的大多数方法。
  
  Spring Security 后，引入了CSRF，默认是开启。CSRF和RESTful技术存在一定有冲突。CSRF默认支持的方法： GET|HEAD|TRACE|OPTIONS，不支持POST。

![9](images/9.png)



- http.authorizeRequests()：请求url权限控制，可以进行路径，权限配置

  ```java
  //请求url权限控制
  http.authorizeRequests()
      //匹配 /login.html 路径，permitAll() 不限制（登录/不登录都可以访问该路径，不进行登录检查）
      .antMatchers("/login.html").permitAll()   
      .antMatchers("/login").permitAll()
      //出去上面匹配路径外，剩下的路径都需要进行登录检查
      .anyRequest().authenticated();
  ```

  

- http.formLogin()：用户登录控制，控制登录相关操作

  ```java
  //用户登录控制
  http.formLogin()
      //指定登录路径
      .loginProcessingUrl("/login")
      //指定登录页面
      .loginPage("/login.html");
  ```

## 7.3 登录路径定制

指定登录路径

```java
//用户登录控制
http.formLogin()
    //指定登录路径
    .loginProcessingUrl("/userLogin")
```

对应的页面需要改进：**action="/userLogin"**

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org/" lang="en">
<head>
  <meta charset="UTF-8">
  <title>用户登录</title>
</head>
<body>
<h1>用户登录</h1>
<form action="/userLogin" method="post">
  用户名：<input type="text" name="username"> <br>
  密码：<input type="text" name="password"><br>
  <input type="submit" value="登录">
</form>
</body>
</html>
```

测试：浏览器上F12观察登录路径

## 7.4 登录参数定制

Spring Security 默认的账号/密码参数：username/password ，

```java
public class UsernamePasswordAuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {

	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
}
```

可以按照下面方式定制

```java
//用户登录控制
http.formLogin()
    .usernameParameter("uname")
    .passwordParameter("pwd");
```

对应的页面需要改进：

<input type="text" **name="uname"**>

<input type="text" **name="pwd"**>

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org/" lang="en">
<head>
  <meta charset="UTF-8">
  <title>用户登录</title>
</head>
<body>
<h1>用户登录</h1>
<form action="/login" method="post">
  用户名：<input type="text" name="uname"> <br>
  密码：<input type="text" name="pwd"><br>
  <input type="submit" value="登录">
</form>
</body>
</html>

```

测试：浏览器上F12观察登录参数



## 7.5 登录成功跳转路径定制

Spring Security 登录成功之后，默认跳转到上一个路径，如果需要定制跳转路径，可以使用下面配置

```java
//用户登录控制
http.formLogin()
    .successForwardUrl("/success")
```

接口

```java
@RequestMapping("/success")
public String success(){
    return "success";
}
```

测试：登录成功观察跳转



## 7.6 登录失败跳转路径定制

Spring Security 登录失败之后，默认跳转到登录页面，如果需要定制跳转路径，可以使用下面配置

```java
//用户登录控制
http.formLogin()
    .failureForwardUrl("/fail")
```

登录失败，跳转/fail路径，因为没有登录，需要放行/fail 登录检查

```java
http.authorizeRequests()
    .antMatchers("/fail").permitAll()
```

接口

```java
@RequestMapping("/fail")
public String fail(){
    return "fail";
}
```

## 7.7 登录成功逻辑定制

前面我们定制登录成功后使用successForwardUrl 跳转某个接口路径，如果是前后端分离项目，要求返回是json格式，那怎么办？又比如，跳转都某个路径前需要执行某个逻辑，这该怎么办？此时可以使用**登录成功处理器**

```java
public class MyAuthenticationSuccessHandler  implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        //response.sendRedirect("/要跳转的路径");
        
        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":200, \"msg\":\"登录成功\", \"data\":{}}";
        response.getWriter().write(data);

    }
}
```

配置处理器

```java
//用户登录控制
http.formLogin()
    .successHandler(new MyAuthenticationSuccessHandler());
```

**注意**：如果也配置successForwardUrl ，以后面配置的为主，也就是后面覆盖前面

```java
http.formLogin()
    .successHandler(new MyAuthenticationSuccessHandler())
    .successForwardUrl("/success")
```

测试：登录成功，观察效果。



## 7.8 登录失败逻辑定制

跟登录成功处理器相对，也有登录失败处理器

```java
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        //response.sendRedirect("/要跳转的路径");

        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":500, \"msg\":\"登录失败\", \"data\":{\"error\":"+exception.getMessage()+"}}";
        response.getWriter().write(data);
    }
}
```

配置处理器

```java
//用户登录控制
http.formLogin()
    .failureHandler(new MyAuthenticationFailureHandler())
```

**注意**：如果也配置failureForwardUrl，以后面配置的为主，也就是后面覆盖前面

```java
http.formLogin()
    .failureHandler(new MyAuthenticationFailureHandler())
    .failureForwardUrl("/fail")
```

测试：登录失败，观察效果。



## 7.9 登出路径定制

Spring Security 默认实现的登出(注销)功能，路径为 /logout，当然也可以定制

```java
//用户登出控制
http.logout()
    .logoutUrl("/userLogout");
```



## 7.10 登出成功跳转路径定制

Spring Security 登录成功之后，默认跳转登录页面，如果有需要可以定制跳转路径

```java
//用户登出控制
http.logout()
    .logoutSuccessUrl("/logoutsuccess")
```

登出之后，logoutsuccess 要放行

```java
//请求url权限控制
http.authorizeRequests()
    .antMatchers("/logoutsuccess").permitAll()
    .anyRequest().authenticated();
```

配置接口

```java
@RequestMapping("/logoutsuccess")
public String logoutsuccess(){
    return "logoutsuccess";
}
```

## 7.11 登出成功逻辑定制

登录成功有逻辑定制，登出成功也可以定制

```java
public class MyLogoutSuccessHandler  implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":200, \"msg\":\"登出成功\", \"data\":{}}";
        response.getWriter().write(data);
    }
}
```

配置登出

```java
//用户登出控制
http.logout()
    .logoutSuccessHandler(new MyLogoutSuccessHandler())
```



# 八、用户授权

## 8.1 RBAC概念复习

Spring Security 登录成功之后第二步就授权，它的授权逻辑跟之前学的RBAC是一个理：居于角色的权限管理系统

*![image-20200707151958178](images/image-20200707151958178.png)*

这里回顾一下以前学RBAC

RBAC：基于角色的访问控制，是面向企业安全策略的一种有效的访问控制方式，其基本思想是，对系统操作的各种权限不是直接授予具体的用户，而是在用户集合与权限集合之间建立一个角色集合，每一种角色对应一组相应的权限，一旦用户被分配了适当的角色后，该用户就拥有此角色的所有操作权限。这样做的好处是，不必在每次创建用户时都进行分配权限的操作，只有分配用户响应的角色即可，而且角色的权限变更必用户的权限变更要少得多，这样将简化用户的权限管理，减少系统的开销。

**大白话：用户扮演某个角色，被允许执行某些操作**。 比如：用户充值成为SVIP，可以下载苍老师高清无码教育影片。

参与角色：

**用户**：代指某个用户，系统是以企业内部项目为例子，操作主体就是用户

**角色**：权限的集合，一个角色包含多种操作权限，一个员工可扮演多种角色，是多对多关心。

**权限**：允许对资源的操作抽象，rbac中权限就是对资源的crud操作。比如：员工添加， 部门删除等。

实现原理

在javaweb中权限的控制，其实就是对请求映射方法控制，如果登录用户有这个权限，允许访问，如果没有权限，不允许访问。居于这个原理，rbac实现步骤如下：

1>自定义一个权限注解：@RequiredPermission，约定贴有这个注解映射方法，必须进行权限校验

2>在需要进行权限校验的请求映射方法中贴上这个这个注解

3>使用拦截器对所有请求进行拦截，每次访问是进行权限校验。

4>如果使用admin登录，不需要拦截



## 8.2 基于配置方式授权

Spring Security 支持RBAC授权，所以授权原理是一样的。具体代码实现方案有2种，一种为配置方式，一种为注解方式；本章节重点讲居于权限的授权。



### 8.2.1 权限表达式

在讲授权与鉴权之前，先讲依赖权限表达式。

权限表达式简单讲就是权限的标记符号，市面上常见表达式方式有3段式，也有2段式

**2段式**

案例：标记用户添加的权限

```java
user:insert
```

上面案例为标准的2段式表示方式，**"资源:操作"**    user表示操作资源， insert 表示操作权限，中间  :   是自定义分割规则，可自行约定

**3段式**

案例：标记会员模块中用户添加权限

```java
member:user:insert
```

这里表示标准的3段式表示方式, **"模块:资源:操作"**  member表示模块，一般的项目会根据业务拆分成很多模块，比如电商项目，有会员模块，商品模块，支付模块等。user表示操作资源， insert 表示操作权限，



**选择**

2段式跟3段式选择，取决于项目规模，大项目，多业务就3段式，小小项目就2段式。

但不管用哪个，底层处理逻辑都是一样的。



### 8.2.2 权限配置授权

先讲权限配置授权再讲角色配置授权

**需求：以部门CRUD操作为例子-权限**

**步骤1：定义部门crud4个接口**

```java
@RestController
@RequestMapping("depts")
public class DepartmentController_Perm {

    @GetMapping("/insert")
    public String insert(){
        return "dept-insert";
    }
    @GetMapping("/update")
    public String update(){
        return "dept-update";
    }
    @GetMapping("/delete")
    public String delete(){
        return "dept-delete";
    }
    @GetMapping("/list")
    public String list(){
        return "dept-list";
    }
}
```

**步骤2：4个接口运行访问的全局**

```java
//请求url权限控制
http.authorizeRequests()
    .antMatchers("/depts/insert").hasAuthority("dept:insert")
    .antMatchers("/depts/update").hasAuthority("dept:update")
    .antMatchers("/depts/delete").hasAuthority("dept:delete")
    .antMatchers("/depts/list").hasAuthority("dept:list")
```

API拓展：

```java
.antMatchers("/depts/list").hasAnyAuthority("dept:list", "dept:query")
```

表示访问 **"/depts/list"**  接口只需要拥有 **"dept:list"** 或 **"dept:query"** 权限即可



**步骤3：配置用户拥有的权限**

此时dafei用户拥有**"dept:insert"**, **"dept:update"** 权限

```java
@Bean
public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("dafei").password("666")
                       .authorities("dept:insert", "dept:update").build());
    manager.createUser(User.withUsername("xiaofei").password("888")
                       .authorities("p2").build());
    return manager;
}
```

**步骤4：测试**

权限校验前需要先登录，使用dafei用户登录， 登录成功后访问下面2组接口

http://localhost:8080/depts/insert  

http://localhost:8080/depts/update

dafei用户有这2个接口权限，正常访问



http://localhost:8080/depts/delete     

http://localhost:8080/depts/list

dafei用户没有这2个接口权限，访问被拒绝

*![image-20240125133948024](images/image-20240125133948024.png)*

### 8.2.3 角色表达式

角色表达是就没有权限表达是那么复杂了，角色就是一个简单标识就行，一般能见名知意就行。比如：ROLE_DEPT_MGR--部门主管角色

角色是权限的集合，用户拥有某个角色，即可拥有角色绑定的权限。

假设：有个部门经理的角色，该角色能对部门进行CRUD操作

```java
角色：dept_mgr
权限：dept:insert  dept:update  dept:delete dept:list
那么：dept_mgr = dept:insert + dept:update + dept:delete + dept:list
```



### 8.2.4 角色配置授权

**需求：以部门CRUD操作为例子-角色**

**步骤1：定义部门crud4个接口**

```java
@RestController
@RequestMapping("depts")
public class DepartmentController_Role {

    @GetMapping("/insert")
    public String insert(){
        return "dept-insert";
    }
    @GetMapping("/update")
    public String update(){
        return "dept-update";
    }
    @GetMapping("/delete")
    public String delete(){
        return "dept-delete";
    }
    @GetMapping("/list")
    public String list(){
        return "dept-list";
    }
}
```

**步骤2：4个接口运行访问的全局**

```java
//请求url权限控制
http.authorizeRequests()
    //.antMatchers("/depts/insert").hasAuthority("dept:insert")
    //.antMatchers("/depts/update").hasAuthority("dept:update")
    //.antMatchers("/depts/delete").hasAuthority("dept:delete")
    //.antMatchers("/depts/list").hasAuthority("dept:list")
    .antMatchers("/depts/insert").hasRole("dept_mgr")
    .antMatchers("/depts/update").hasRole("dept_mgr")
    .antMatchers("/depts/delete").hasRole("hr")
    .antMatchers("/depts/list").hasRole("hr")
```

API拓展：

```java
.antMatchers("/depts/list").hasAnyRole("dept_mgr", "hr")
```

表示访问 **"/depts/list"**  接口只需要拥有 **"dept_mgr"** 或 **"hr"**角色 即可

**步骤3：配置用户拥有的权限**

此时dafei用户拥有**"dept_mgr"** 权限

```java
@Bean
public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("dafei").password("666")
                       .roles("dept_mgr").build());
    manager.createUser(User.withUsername("xiaofei").password("888")
                       .authorities("p2").build());
    return manager;
}
```

**步骤4：测试**

权限校验前需要先登录，使用dafei用户登录， 登录成功后访问下面2组接口

http://localhost:8080/depts/insert  

http://localhost:8080/depts/update

dafei用户拥有dept_mgr角色，而上面2个接口需要的也是dept_mgr角色，所以可以访问



http://localhost:8080/depts/delete     

http://localhost:8080/depts/list

dafei用户拥有dept_mgr角色，而上面2个接口需要的也是hr角色，所以访问被拒绝



## 8.3 基于注解方式授权

上面使用配置方式，操作相对简单，但是开发中很少使用，原因：当接口多了之后，每个都要配置一遍，非常麻烦。Spring Security 2.x之后，引入注解的方式，极大简化授权与鉴权步骤。

Spring Security 注解方式授权与鉴权涉及到2个核心的注解：**@PreAuthorize**，**@Secured**

其中**@PreAuthorize** 是基于权限授权(也可以基于角色)，**@Secured**是基于角色授权，先看基于权限授权

> 注意：处理上面上面2个注解之后，还是**"@PostAuthorize"**，**"@RolesAllowed"** 注解，课下可以自个拓展



### 8.3.1 权限注解授权

**需求：以部门CRUD操作为例子-注解-权限**

**步骤1：配置启动注解**

默认情况下Spring Security是不支持注解鉴权的，此时需要配置类中开启

```java
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    ...
}
```

**步骤2：定义部门crud4个接口**

注意：使用注解标记方法接口需要的权限

```java
@RestController
@RequestMapping("depts")
public class DepartmentController_ann_perm {

    @PreAuthorize("hasAnyAuthority('dept:insert')")
    @GetMapping("/insert")
    public String insert(){
        return "dept-insert";
    }
    
    @PreAuthorize("hasAnyAuthority('dept:update')")
    @GetMapping("/update")
    public String update(){
        return "dept-update";
    }
    
    @PreAuthorize("hasAnyAuthority('dept:delete')")
    @GetMapping("/delete")
    public String delete(){
        return "dept-delete";
    }
    
    @PreAuthorize("hasAnyAuthority('dept:list')")
    @GetMapping("/list")
    public String list(){
        return "dept-list";
    }
}
```

**步骤3：配置用户拥有的权限**

```java
@Bean
public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("dafei").password("666")
                       .authorities("dept:insert", "dept:update").build());
    manager.createUser(User.withUsername("xiaofei").password("888")
                       .authorities("p2").build());
    return manager;
}
```

**步骤4：移除http.authorizeRequests中权限配置**

```java
//请求url权限控制
http.authorizeRequests()
    //.antMatchers("/depts/insert").hasAuthority("dept:insert")
    //.antMatchers("/depts/update").hasAuthority("dept:update")
    //.antMatchers("/depts/delete").hasAuthority("dept:delete")
    //.antMatchers("/depts/list").hasAuthority("dept:list")
```

**步骤5：测试**

权限校验前需要先登录，使用dafei用户登录， 登录成功后访问下面2组接口

http://localhost:8080/depts/insert  

http://localhost:8080/depts/update

dafei用户有这2个接口权限，正常访问

http://localhost:8080/depts/delete     

http://localhost:8080/depts/list

dafei用户没有这2个接口权限，访问被拒绝

### 8.3.2 角色注解授权

#### 8.3.2.1 方式一：@PreAuthorize

**需求：以部门CRUD操作为例子-注解-角色**

**步骤1：配置启动注解**

默认情况下Spring Security是不支持注解鉴权的，此时需要配置类中开启

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    ...
}
```

**步骤2：定义部门crud4个接口**

注意：使用注解标记方法接口需要的权限

```java
@RestController
@RequestMapping("depts")
public class DepartmentController_ann_role {

    @PreAuthorize("hasAnyRole('dept_mgr')")
    @GetMapping("/insert")
    public String insert(){
        return "dept-insert";
    }
    
    @PreAuthorize("hasAnyRole('dept_mgr')")
    @GetMapping("/update")
    public String update(){
        return "dept-update";
    }
    
    @PreAuthorize("hasAnyRole('hr')")
    @GetMapping("/delete")
    public String delete(){
        return "dept-delete";
    }
    
    @PreAuthorize("hasAnyRole('hr')")
    @GetMapping("/list")
    public String list(){
        return "dept-list";
    }
}
```

**步骤3：配置用户拥有的权限**

```java
@Bean
public UserDetailsService userDetailsService() {
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("dafei").password("666")
                       .roles("dept_mgr").build());
    manager.createUser(User.withUsername("xiaofei").password("888")
                       .authorities("p2").build());
    return manager;
}
```

**步骤4：移除http.authorizeRequests中权限配置**

```java
//请求url权限控制
http.authorizeRequests()
    //.antMatchers("/depts/insert").hasRole("dept_mgr")
    //.antMatchers("/depts/update").hasRole("dept_mgr")
    //.antMatchers("/depts/delete").hasRole("hr")
    //.antMatchers("/depts/list").hasAnyRole("hr")
```

**步骤5：测试**

权限校验前需要先登录，使用dafei用户登录， 登录成功后访问下面2组接口

http://localhost:8080/depts/insert  

http://localhost:8080/depts/update

dafei用户拥有dept_mgr角色，而上面2个接口需要的也是dept_mgr角色，所以可以访问



http://localhost:8080/depts/delete     

http://localhost:8080/depts/list

dafei用户拥有dept_mgr角色，而上面2个接口需要的也是hr角色，所以访问被拒绝



#### 8.3.2.2 方式二：@Secured

配置文件类

```java
//@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    ...
}
```

controller代码

```java
@RestController
@RequestMapping("depts")
public class DepartmentController_ann_role {

    @Secured("ROLE_dept_mgr")
    @GetMapping("/insert")
    public String insert(){
        return "dept-insert";
    }
    
    @Secured("ROLE_dept_mgr")
    @GetMapping("/update")
    public String update(){
        return "dept-update";
    }
    
    @Secured("ROLE_hr")
    @GetMapping("/delete")
    public String delete(){
        return "dept-delete";
    }
    
    @Secured("ROLE_hr")
    @GetMapping("/list")
    public String list(){
        return "dept-list";
    }
}
```

其他操作同方式一。

注意：Spring Security 会自动拼接ROLE_前缀，所有controller必须在角色前面明确加上ROLE_前缀

## 8.4 权限异常处理

当出现权限异常时，默认返回403异常页面，可以通过exceptionHandling进行控制

### 8.4.1 **页面跳转**

**步骤1：定义nopermission.html**

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org/" lang="en">
<head>
  <meta charset="UTF-8">
  <title>没有权限</title>
</head>
<body>
<h1>没有权限</h1>
</body>
</html>

```

**步骤2：配置权限异常跳转页面**

```java
//异常控制
http.exceptionHandling()
    .accessDeniedPage("/nopermission.html");
```



### 8.4.2 **Json格式返回**

**步骤1：定义权限异常处理器**

```java
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":403, \"msg\":\"没有权限\", \"data\":{\"error\":"+accessDeniedException.getMessage()+"}}";
        response.getWriter().write(data);
    }
}
```

**步骤2：配置权限异常处理器**

```java
//异常控制
http.exceptionHandling()
    .accessDeniedHandler(new MyAccessDeniedHandler())
```



## 8.5 授权小结

了解配置方式授权跟注解方式授权，也了解了权限表示式授权跟角色授权，那开发中怎么选择呢？

**配置vs注解---->注解**

**表达式是vs角色---->混用，表达式灵活，可定制；角色简单集成，大开大合。**



# 九、原理解析

## 9.1 框架设计原理

Spring Security 认证与授权都是建立在Servlet 过滤器体系中的，所以研究认证原理，必须先理解Servlet 过滤体系。先看两张图：

**图一**

![image-20240126204517490](images/image-20240126204517490.png)

客户端发起请求到controller处理请求这个过程，最先经过的是filter过滤器。

**图二**

*![filterchain](images/filterchain.png)*

当请求经过filter过滤器时，Servlet容器会构建一个`FilterChain`过滤器链，里面包含所有`Filter` 实例，每个过滤器都根据请求URI的路径来执行过滤逻辑。



有了上面铺垫，那精彩来了，Spring Security 就是在这个servlet 过滤体系借助Spring 容器委托机制，嵌入自己过滤逻辑。如下图：

*![securityfilterchain](images/securityfilterchain.png)*

Spring 提供了一个名为 `DelegatingFilterProxy`的 `Filter` 实现，允许在 Servlet 容器的生命周期和 Spring 的 `ApplicationContext` 之间建立桥梁。

借助这个桥梁，Spring Security 定制一个过滤器链代理对象：FilterChainProxy，用于对接Spring Security 它自己的过滤器链，进而实现认证与授权过滤。



## 9.2 认证原理解析

### 9.2.1 详细版

Spring Security 认证操作过程大体如下图：

![认证](images/认证.png)



**UsernamePasswordAuthenticationFilter**-用于处理基于用户名和密码的身份验证。

- 提取用户名和密码：当用户提交登录请求时，该过滤器会从请求中提取出用户名和密码信息。

- 封装成 Authentication 对象：将提取到的用户名和密码封装成一个 UsernamePasswordAuthenticationToken 对象，该对象实现了 Spring Security 的 Authentication 接口。

- 调用 AuthenticationManager 进行身份验证：将封装好的 Authentication 对象传递给 AuthenticationManager 进行身份验证。AuthenticationManager 是 Spring Security 的核心接口，负责处理身份验证相关的操作。

- 处理身份验证结果：根据身份验证结果，如果验证成功，则生成一个已认证的 Authentication 对象，并将其存储在 SecurityContextHolder 中；如果验证失败，则根据配置的失败处理器进行相应的处理，例如重定向到登录页面或返回错误信息。

  

**UsernamePasswordAuthenticationToken**-是一个身份验证的凭证对象，用于封装用户名和密码信息。

- 实现了 Spring Security 的 Authentication 接口，封装待验证的账号与密码

  

**Authentication** - 接口，一个身份验证的抽象对象，用于表示一个已认证的用户身份。它的主要作用是封装用户的身份信息，并在身份验证过程中传递和存储该信息。

- 封装用户身份信息：Authentication 接口封装了用户的身份信息，例如用户名、密码、权限等。这些信息通常是从用户提交的身份认证凭证中提取出来的-比如：UsernamePasswordAuthenticationToken。

- 传递和存储身份信息：在身份验证过程中，Authentication 对象会被传递给相应的 AuthenticationProvider 进行验证。如果验证成功，则该对象会被存储在 SecurityContextHolder 中，以便后续的授权操作使用。



**UsernamePasswordAuthenticationFilter**- 一个用于认证的基本 Filter。用于处理身份验证的过滤器，是UsernamePasswordAuthenticationFilter父类



**AuthenticationManager** - 是一个核心接口，用于处理身份验证相关的操作。它的主要作用是尝试对用户进行身份验证，并返回一个已认证的 Authentication 对象。



**ProviderManager** -实现了AuthenticationManager接口，是一个身份验证管理器，管理多个 AuthenticationProvider 实例。可以根据配置策略选择不同AuthenticationProvider 实例实现验证。例如用户名密码验证、LDAP 验证、OpenID 验证、OAuth2验证等



**AuthenticationProvider** - 身份验证的核心组件之一，由 ProviderManager 指定，用于对用户进行身份验证。



**DaoAuthenticationProvider**- AuthenticationProvider 接口的一个具体实现之一，用于处理基于数据库的身份验证。



**UserDetailsService**-用于获取用户信息的核心接口，主要用于支持基于用户名密码的身份验证。开发者可以通过实现 UserDetailsService 接口，来自定义获取用户信息的逻辑。



**UserDetails**-用于表示用户详细信息的核心接口，它包含了用户的身份信息和权限信息。



**SecurityContextHolder** - 提供了一个用于存储和获取当前用户安全上下文信息的静态容器。



**SecurityContext** - 是一个接口，通过 SecurityContextHolder 类获得的，用于表示当前用户的安全上下文信息，包含了当前用户的认证信息和授权信息。



**Principal**-表示当前用户的主体，即当前用户的身份信息。它通常用于获取当前经过认证的用户的身份信息。



**Credentials**-用于表示当前经过认证的用户的凭据信息，比如密码、令牌等。



**Authorities**-用于表示当前经过认证的用户所拥有的权限信息。它代表了用户可以访问的资源或执行的操作



*![securitycontextholder](images/securitycontextholder.png)*



### 9.2.2 **简化版**

*![image-20220620115942257](images/image-20220620115942257.png)*

### 9.2.3 **Debug源码走读**

从上面的流程分析，可以看出，登录认证的入口点是：UsernamePasswordAuthenticationFilter，用idea查看它集成体系

![image-20240127210247332](images/image-20240127210247332.png)

其中实现Filter接口，那就意味着属于Servlet过滤体系，那么抓住过滤体系中入口：doFilter 方法作为突破口

![image-20240127210137167](images/image-20240127210137167.png)

Filter 最直接的GenericFilterBean实现类为抽象类，并没有实现doFilter方法

```java
public abstract class GenericFilterBean implements Filter....{
    ....
}
```

根据抽象类，抽象方法使用特性，doFilter方法的实现会交个AbstractAuthenticationProcessingFilter子类实现

```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean...{
   	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
        .....
    }
}
```

所以debug模式第一个断点就出现了：**AbstractAuthenticationProcessingFilter**--**doFilter**

![image-20240127210932050](images/image-20240127210932050.png)

F8往下执行到212行时，按F7进入真实调用方法

![image-20240127211134396](images/image-20240127211134396.png)

注意：attemptAuthentication 是一个抽象方法，**AbstractAuthenticationProcessingFilter**并没有实现，交给其子类：**UsernamePasswordAuthenticationFilter** 实现。

```java
public class UsernamePasswordAuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
 
    	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
            ....
        }
}
```

所以debug模式第二个断点就出现了：**UsernamePasswordAuthenticationFilter**--**attemptAuthentication**

![image-20240127211525254](images/image-20240127211525254.png)

F5继续往下走，看到UsernamePasswordAuthenticationToken的封装：封装了账号与密码

![image-20240127212510298](images/image-20240127212510298.png)

F5继续往下走，就到AuthenticationManager

![image-20240127212623971](images/image-20240127212623971.png)

```java
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean...{
	protected AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}
}
```

AbstractAuthenticationProcessingFilter 委托：AuthenticationManager接口实现类ProviderManager 执行authenticate认证

```java
public class ProviderManager implements AuthenticationManager...{
    	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
            ...
        }
}
            
```

所以debug模式第三个断点就出现了：**ProviderManager**--**authenticate**

![image-20240127213153862](images/image-20240127213153862.png)

F5继续，175行按F7进入具体认证校验逻辑

![image-20240127213822887](images/image-20240127213822887.png)

顺着流程，F7之后进入

```java
public abstract class AbstractUserDetailsAuthenticationProvider implements
		AuthenticationProvider{
    	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
            ...
        }
}
```

所以debug模式第四个断点就出现了：**AbstractUserDetailsAuthenticationProvider**--**authenticate**

![image-20240127214319787](images/image-20240127214319787.png)

F5继续执行，来到这个位置

![image-20240127214410692](images/image-20240127214410692.png)

retrieveUser方法AbstractUserDetailsAuthenticationProvider类的抽象方法，没有具体实现，F7后会直接到AbstractUserDetailsAuthenticationProvider子类：DaoAuthenticationProvider

```java
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    	protected final UserDetails retrieveUser(String username,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
            ....
        }
}
```

所以debug模式第五个断点就出现了：**DaoAuthenticationProvider**--**retrieveUser**

![image-20240127214904517](images/image-20240127214904517.png)

最后使用哪种策略实现loadUserByUsername获取用户信息，就看项目配置类，默认使用InMemoryUserDetailsManager

![image-20240127215200349](images/image-20240127215200349.png)

然后一直F5，知道执行到**AbstractUserDetailsAuthenticationProvider**的additionalAuthenticationChecks

![image-20240127220710930](images/image-20240127220710930.png)

F7进去，进入**DaoAuthenticationProvider**的**additionalAuthenticationChecks**实现密码比对

![image-20240127220835077](images/image-20240127220835077.png)

如果密码匹配没有任何问题，那就可以放行debug流程即可，因为已经算认证成功了，至于认证成功后续操作在AbstractAuthenticationProcessingFilter 类的doFilter方法里面。

![image-20240127221146389](images/image-20240127221146389.png)

至此，debug流程结束，Spring Security 认证源码走读完毕



## 9.3 授权原理解析

Spring Security的授权跟认证都是基于Servlet过滤器实现，看下图：

*![image-20240128155938606](images/image-20240128155938606.png)*

请求通过各种filter之后，最后一层是FilterSecurityInterceptor，而这里就是SpringSecurity鉴权起点。此处要注意FilterSecurityInterceptor 命中带有Interceptor，但它本质还是一个Filter。

### 9.3.1 详细版

Spring Security 鉴权操作过程大体如下图：

![鉴权](images/鉴权.png)

**FilterInvocation**-用于封装 HTTP 请求信息的对象，包括请求的 URL、HTTP 方法、请求参数、头部信息等。



**FilterSecurityInterceptor**-一个安全过滤器，用于实现基于 URL 的访问控制负责将拦截到的 HTTP 请求交给访问决策管理器（AccessDecisionManager）进行访问决策（鉴权）。



**AbstractSecurityInterceptor**-是一个抽象类，它是所有安全拦截器的基类。它定义了一些通用的方法和属性，用于实现访问控制功能。



**SecurityMetadataSource**-用于管理受保护资源的安全元数据，包括访问控制规则、认证要求等。



ConfigAttribute-一个接口，它表示受保护资源的访问控制配置属性，简单理解为一个url地址权限配置



**AccessDecisionManager**-是用于进行访问控制决策的关键组件，它是一个接口，选择选择具体实现类实现决策



**AffirmativeBased**-是 AccessDecisionManager 接口的一个实现类，它实现了肯定策略的访问控制决策。



**AccessDecisionVoter**-用于进行访问控制决策的组件，其作用是根据给定的安全上下文和受保护资源的安全元数据，对访问请求进行投票，决定是否允许特定用户执行特定操作。



WebExpressionVoter-是 AccessDecisionVoter 接口的一个实现类，用于进行基于表达式的访问控制决策



WebExpressionConfigAttribute-是 ConfigAttribute 接口的一个实现类，用于表示基于表达式的访问控制配置属性。



**ExpressionUtils**-一个实用工具类，用于处理表达式相关的操作。



**SpelExpression**-是 Spring Expression Language（SpEL）的一种表达式类型，用于定义和评估访问控制规则。



### 9.3.2 简化版

![202112070824099.png](images/202112070824099.png)

### 9.3.3 Debug源码走读

需**求：登录成功后，访问/depts/update请求**

```java
//认证与授权
http.authorizeRequests()
    .antMatchers("/depts/update").hasAuthority("dept:update")
```

用户拥有dept:update权限

```java
manager.createUser(User.withUsername("dafei").password("666").authorities("dept:update").build());
```

**走读开始**

从上面的流程分析，可以看出，鉴权的入口点是：FilterSecurityInterceptor，用idea查看它集成体系

*![image-20240129004351456](images/image-20240129004351456.png)*

servlet 过滤器体系，入口都是doFilter

所以debug模式第一个断点就出现了：**FilterSecurityInterceptor**-**doFilter**

![image-20240129120827904](images/image-20240129120827904.png)

新建一个类：FilterInvocation，用于保存request，response，过滤链chain对象，目的让整个鉴权流程随时获取到这3对象。

*![image-20240129144244361](images/image-20240129144244361.png)*



F7进入invoke方法，进入方法

![image-20240129121112531](images/image-20240129121112531.png)

super.beforeInvocation 调用父类鉴权逻辑：AbstractSecurityInterceptor

所以debug模式第二个断点就出现了：**AbstractSecurityInterceptor**--**beforeInvocation**

![image-20240129143605453](images/image-20240129143605453.png)

F5继续执行，执行到

```java
protected InterceptorStatusToken beforeInvocation(Object object) {
    ...
    Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
}
```

*![image-20240129144345818](images/image-20240129144345818.png)*

debug信息可以看出，attributes就是从SpringSecurityConfig 中加载当前访问接口要求的权限表达式列表

F5继续执行，执行到

```java
protected InterceptorStatusToken beforeInvocation(Object object) {
    ...
    Authentication authenticated = authenticateIfRequired();
}
```

![image-20240129145541880](images/image-20240129145541880.png)

可以猜测，后续的逻辑就是对比：ConfigAttribute  跟 Authentication 中的权限表达式啦。

继续F5，遇到下面：this.accessDecisionManager.decide, F7进入，就到：AccessDecisionManager.decide 接口方法，因为AccessDecisionManager是接口，需要确认实现类，默认选择：AffirmativeBased

*![image-20240129150322155](images/image-20240129150322155.png)*

所以debug模式第三个断点就出现了：**AffirmativeBased**--**decide**

![image-20240129150437409](images/image-20240129150437409.png)

继续F5， 然后F7进入voter.vote进行权限投票，流程走到新的接口：AccessDecisionVoter-vote，AccessDecisionVoter为接口，流程找其实现类**，WebExpressionVoter**

所以debug模式第个断点就出现了：WebExpressionVoter--**vote**

![image-20240129151125898](images/image-20240129151125898.png)

继续F5，直到

```java
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {
 		public int vote(Authentication authentication, FilterInvocation fi,
			Collection<ConfigAttribute> attributes) {
            ....
            return ExpressionUtils.evaluateAsBoolean(weca.getAuthorizeExpression(), ctx) ? ACCESS_GRANTED
				: ACCESS_DENIED;    
        }
}
```

这里的ExpressionUtils.evaluateAsBoolean 就是权限表达式校验，俗称鉴权。如果想继续深入，就可以对evaluateAsBoolean方法继续F7查看方法逻辑。

至此，debug流程结束，Spring Security 鉴权源码走读完毕



# 十、会话管理

## 10.1 获取当前登录用户

用户认证通过后，为了避免用户的每次操作都进行认证可将用户的信息保存在会话中。spring security提供会话管理，认证通过后将身份信息放入SecurityContextHolder上下文，SecurityContext与当前线程进行绑定，方便获取 用户身份。 

```java
@GetMapping("/getUsername")
public String getUsername(){
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    Object principal = authentication.getPrincipal();
    String username = "";
    if(principal instanceof UserDetails){
        username = ((UserDetails) principal).getUsername();
    }else{
        username=  principal.toString();
    }
    return username;
} 
```

测试：登录成功后访问：http://localhost:8080/getUsername



## 10.2 会话控制

Spring Security 提供了4种会话控制，方便应对各种场景。

| 机制       | 描述                                                         |
| :--------- | :----------------------------------------------------------- |
| always     | 如果没有session存在就创建一个                                |
| ifRequired | 如果需要就创建一个Session（默认）登录时                      |
| never      | SpringSecurity 将不会创建Session，但是如果应用中其他地方创建了Session，那么Spring Security将会使用它。 |
| stateless  | SpringSecurity将绝对不会创建Session，也不使用Session         |

策略由一个枚举类统一管理。

```java
public enum SessionCreationPolicy {
	ALWAYS,
	NEVER,
	IF_REQUIRED,
	STATELESS
}
```

通过以下配置方式实现会话策略配置。

```java
//会话控制
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
```

默认情况下，Spring Security会为每个登录成功的用户会新建一个Session，就是**ifRequired** 。 

若选用**never**，则指示Spring Security对登录成功的用户不创建Session了，但若你的应用程序在某地方新建了session，那么Spring Security会用它的。 

若使用**stateless**，则说明Spring Security对登录成功的用户不会创建Session了，你的应用程序也不会允许新建session。并且它会暗示不使用cookie，所以每个请求都需要重新进行身份验证。这种无状态架构适用于REST API 及其无状态认证机制。 后续讲的JWT认证就选择这个策略。



**选择**：

传统前后端不分离项目：**ifRequired**

最新前后端分类项目：**stateless**  + 自定义用户信息存储



# 十一、JWT认证



## 11.0 前置知识点

**思考1：为什么要认证？**

**思考2：认证实现方式有哪些？**

需求：访问某些接口，必须确定当前访问的用户为系统用户



## 11.1 JWT概念

官网：https://jwt.io/

*![image-20230415222934602](images/image-20230415222934602.png)*

整理一下：

JSON Web Token，简称 [**JWT**]()，读音是 [dʒɒt]（ jot 的发音），是一个基于 RFC 7519 的开放数据标准，它定义了一种宽松且紧凑的数据组合方式。其作用是：**JWT是一种加密后数据载体，可在各应用之间进行数据传输**。

## 11.2 JWT组成

一个 [**JWT**]() 通常有 HEADER (头)，PAYLOAD (有效载荷)和 SIGNATURE (签名)三个部分组成，三者之间使用“.”链接，格式如下：

```js
header.payload.signature
```

![image-20230415203638545](images/image-20230415203638545.png)

**一个简单的JWT案例：**

```java
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9   //header
.eyJ1c2VyX2luZm8iOlt7ImlkIjoiMSJ9LHsibmFtZSI6ImRhZmVpIn0seyJhZ2UiOiIxOCJ9XSwiaWF0IjoxNjgxNTcxMjU3LCJleHAiOjE2ODI3ODM5OTksImF1ZCI6InhpYW9mZWkiLCJpc3MiOiJkYWZlaSIsInN1YiI6ImFsbHVzZXIifQ  //payload
.v1TxJ0mngnVx4t9O3uibAHPSLUyMM7sUM06w8ODYjuE //signature
```

> 注意：三者之间有一个点号(“.”)相连

### 11.2.1 Header组成

JWT的头部承载两部分信息：

- 声明类型，默认是JWT
- 声明加密的算法 常用的算法：HMAC 、RSA、ECDSA等

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**alg**：表示签名的算法，默认是 HMAC SHA256（写成 HS256）；

**typ**： 表示令牌（token）的类型，JWT 令牌统一写为 `JWT`。

使用Base64加密，构成了JWT第一部分-header：

```java
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

### 11.2.2 Payload组成

Payload 部分也是一个 JSON 对象，用来存放实际需要传递的有效信息。

**标准载荷**：有很多，建议使用，但不强制，对JWT信息作补充。

| 标准载荷              | 介绍                                   |
| --------------------- | -------------------------------------- |
| iss (issuer)          | 签发人（谁签发的）                     |
| exp (expiration time) | 过期时间，必须要大于签发时间           |
| sub (subject)         | 主题（用来做什么）                     |
| aud (audience)        | 受众(给谁用的)比如：http://www.xxx.com |
| nbf (Not Before)      | 生效时间                               |
| iat (Issued At)       | 签发时间                               |
| jti (JWT ID)          | 编号，JWT 的唯一身份标识               |

**自定义载荷**：可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息。但不建议添加敏感信息，因为该部分在客户端可解密。

```json
{
    "user_info": [
      {
        "id": "1"
      },
      {
        "name": "dafei"
      },
      {
        "age": "18"
      }
    ],
    "iat": 1681571257,
    "exp": 1682783999,
    "aud": "xiaofei",
    "iss": "dafei",
    "sub": "alluser"
}
```

使用Base64加密，构成了JWT第二部分-payload：

```java
eyJ1c2VyX2luZm8iOlt7ImlkIjoiMSJ9LHsibmFtZSI6ImRhZmVpIn0seyJhZ2UiOiIxOCJ9XSwiaWF0IjoxNjgxNTcxMjU3LCJleHAiOjE2ODI3ODM5OTksImF1ZCI6InhpYW9mZWkiLCJpc3MiOiJkYWZlaSIsInN1YiI6ImFsbHVzZXIifQ
```

### 11.2.3 signature组成

Signature 部分是对前两部分的签名，防止数据篡改。

首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名。

```java
signature = HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用"点"（`.`）分隔，就可以返回给用户。

**因为有这个密钥的存在，所以即便调用方偷偷的修改了前两部分的内容，在验证环节就会出现签名不一致的情况，所以保证了安全性。**

使用Base64加密，构成了JWT第三部分-signature：

```java
l6JdYARw4IHmjliSbh9NP6ji1L15qVneWTJU5noQ-k8
```

## 11.3 在线生成/解析JWT

### 11.3.1 编码工具

地址：https://tooltt.com/jwt-encode/

![image-20230415231151726](images/image-20230415231151726.png)



### 11.3.2 解码工具

地址：https://tool.box3.cn/jwt.html

![image-20230415231215566](images/image-20230415231215566.png)



## 11.4 JWT编程

### 11.4.1 能够做啥

- 令牌认证

  这是使用JWT的最常见方案。一旦用户登录，每个后续请求将包括JWT，从而允许用户访问该令牌允许的路由，服务和资源；常用于前后端分离项目。

- 信息交换

  JWT是在各方之间安全地传输信息的好方法。因为可以对JWT进行签名（例如，使用公钥/私钥对），所以您可以确保发件人是他们所说的人。此外，由于签名是使用标头和有效负载计算的，因此您还可以验证内容是否遭到篡改。

这里重点讲解JWT认证。

### 11.4.2 代码实现

**步骤1：引入依赖**

```xml
<!--引入jwt-->
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>java-jwt</artifactId>
  <version>3.4.0</version>
</dependency>
```

**步骤2：生成token**

```java
//生成令牌
@Test
public void testCreate(){

    String token = JWT.create()
        .withClaim("username", "dafei")//设置自定义用户名
        .sign(Algorithm.HMAC256("abcdefghijklmnopqrstuvwxyz"));//设置签名 保密 复杂
    //输出令牌
    System.out.println(token);
}
```

返回结果：

```java
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsicGhvbmUiLCIxNDMyMzIzNDEzNCJdLCJleHAiOjE1OTU3Mzk0NDIsInVzZXJuYW1lIjoi5byg5LiJIn0.aHmE3RNqvAjFr_dvyn_sD2VJ46P7EGiS5OBMO_TI5jg
```

**步骤3：解析token**

```java
//解析令牌
@Test
public void testParse(){

    String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsicGhvbmUiLCIxNDMyMzIzNDEzNCJdLCJleHAiOjE1OTU3Mzk0NDIsInVzZXJuYW1lIjoi5byg5LiJIn0.aHmE3RNqvAjFr_dvyn_sD2VJ46P7EGiS5OBMO_TI5jg";
    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("abcdefghijklmnopqrstuvwxyz")).build();
    DecodedJWT decodedJWT = jwtVerifier.verify(token);
    System.out.println("用户名: " + decodedJWT.getClaim("username").asString());
}
```



**步骤4：设置jwt有效时间**

```java
//设置令牌有效时间
@Test
public void testExpired() throws InterruptedException {

    String token = JWT.create()
        .withClaim("username", "dafei")//设置自定义用户名
        .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 1000L))   //5s中
        .sign(Algorithm.HMAC256("abcdefghijklmnopqrstuvwxyz"));//设置签名 保密 复杂
    //输出令牌
    System.out.println(token);

    Thread.sleep(6000);
    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("abcdefghijklmnopqrstuvwxyz")).build();
    DecodedJWT decodedJWT = jwtVerifier.verify(token);
    System.out.println("用户名: " + decodedJWT.getClaim("username").asString());
}
```



常见的异常

```java
- SignatureVerificationException:					签名不一致异常
- TokenExpiredException:    						令牌过期异常
- AlgorithmMismatchException:						算法不匹配异常
- InvalidClaimException:							失效的payload异常
```



## 11.5 JWT认证

### 11.5.1 基于Session认证

![image-20221103110631400](images/image-20221103110631400.png)

**缺陷：**

- 每个用户经过我们的应用认证之后，我们的应用都要在服务端做一次记录，以方便用户下次请求的鉴别，通常而言session都是保存在内存中，而随着认证用户的增多，服务端的开销会明显增大

- 因为是基于cookie来进行用户识别的, cookie如果被截获，用户就会很容易受到跨站请求伪造的攻击。
- 前后端分离项目，客户端可能有多种，有些不一定支持cookie/session



### 11.5.2 基于JWT认证

*![image-20200726183248298](images/image-20200726183248298.png)*

**优点：**

- 简洁: 可以通过URL，POST参数或者在HTTP header发送，因为数据量小，传输速度也很快
- 自包含：负载中包含了所有用户所需要的信息，避免了多次查询数据库
- 因为Token是以JSON加密的形式保存在客户端的，所以JWT是跨语言的，原则上任何web形式都支持。



### 11.5.3 代码实现

JWT认证实现存在2种方式：

- 定制JWT过滤器，嵌入SpringSecurity 过滤链体系
- 重写认证处理器DaoAuthenticationProvider的additionalAuthenticationChecks方法

这里讲第一种方式：自定义JWT过滤器。



**需求：Spring Security 集成JWT实现认证。**

**实现思路**：

1>自定义登录接口，使用AuthenticationManager实现登录--构建jwt

2>自定义jwt filter 拦截所有请求，--校验jwt

​     - 检查jwt是否合法

​     - 检查jwt中用户信息与数据库(内存/redis)用户信息是否一致

3>自定义登录异常处理



**步骤1：定制JWT工具类**

```java
public class JWTUtils {

    public static  String scret = "abcdefjhijklmnopqrstuvwxyz";

    public static Long time = 7 * 24 * 60 * 60 * 6000L;  //7天

    public  static String createTokenMap(Map<String,String> map) {

        JWTCreator.Builder builder = JWT.create();
        for (Map.Entry<String, String> entry : map.entrySet())     {
            builder.withClaim(entry.getKey(), entry.getValue());

        }
        builder.withExpiresAt(new Date(System.currentTimeMillis() + time));
        String token = builder.sign(Algorithm.HMAC256(scret));
        return token;
    }
    public static String createToken(String key , String value) {

        JWTCreator.Builder builder = JWT.create();
        builder.withClaim(key,value);
        String token = builder.sign(Algorithm.HMAC256(scret));
        return token;
    }

    public  static String getToken(String token,String key){
        //先验证签名
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(scret)).build();
        //验证其他信息
        DecodedJWT verify = verifier.verify(token);
        String value = verify.getClaim(key).asString();
        return value;
    }
    public static  boolean isExpired(String token){
        //先验证签名
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(scret)).build();

        try {
            //验证其他信息
            DecodedJWT verify = verifier.verify(token);
            return true;
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
}
```

**步骤2：重写一份新的配置文件**

备份之前那份SpringSecurityConfig， 并注释掉贴的注解

![image-20240129220041041](images/image-20240129220041041.png)

重新配置写一个新的SpringSecurityConfig类

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    //配置用户信息服务-本地
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("dafei").password("666")
                .roles("dept_mgr").authorities("dept:update").build());
        manager.createUser(User.withUsername("xiaofei").password("888")
                .authorities("p2").build());
        return manager;
    }

    //密码加密器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
    
    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    //自定义配置
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //禁用csrf保护-前后端分离项目需要禁用，认证鉴权项目也要需要禁用
        http.csrf().disable();

        //请求url权限控制
        http.authorizeRequests()
            	.antMatchers("/jwt/login").permitAll()
                .anyRequest().authenticated();

        //用户登录控制
        http.formLogin()
                .failureHandler(new MyAuthenticationFailureHandler())
                .successHandler(new MyAuthenticationSuccessHandler());


        //会话控制
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }
}

```

注意：删除一些不需要的，添加一些必须得

**添加1**

```java
//请求url权限控制
http.authorizeRequests()
    .antMatchers("/jwt/login").permitAll()
    .anyRequest().authenticated();
```

放行后续定义的/jwt/login接口

**添加2**

```java
@Bean
@Override
protected AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
}
```

创建对象AuthenticationManager，交给容器管理，后面需要使用该对象完成自定义登录。

**添加3**

```java
//会话控制
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
```

JWT为无状态登录，数据并不会缓存到session中，所以需要明确指定无状态登录，即：不使用session登录

**步骤3：定制登录逻辑**

登录成功，返回jwt，登录失败抛异常。

```java
@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/jwt/login")
    public String login(String uname, String pwd){
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uname,pwd);
        Authentication authenticate = authenticationManager.authenticate(token);
        if(authenticate != null && authenticate.isAuthenticated()){
            //登录成功
            return JWTUtils.createToken("username", uname);
        }
        throw new RuntimeException("账号与密码出错");
    }
}
```

**步骤4：定制jwt检验过滤器**

```java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        httpServletResponse.setContentType("application/json;charset=utf-8");

        String url = httpServletRequest.getRequestURI();
        if(url.startsWith("/jwt/login")){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        String token = httpServletRequest.getHeader("token");
        if(!StringUtils.hasText(token)){
            httpServletResponse.getWriter().write("token 不能为空");
            return;
        }
        if(!JWTUtils.isExpired(token)){
            httpServletResponse.getWriter().write("token 失效");
            return;
        }

        String username = JWTUtils.getToken(token, "username");

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null){
            httpServletResponse.getWriter().write("token校验失败，请重新登录");
            return;
        }
        var authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
```

**步骤5：配置过滤器**

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;


    //配置用户信息服务-本地
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("dafei").password("666")
                .roles("dept_mgr").authorities("dept:update").build());
        manager.createUser(User.withUsername("xiaofei").password("888")
                .authorities("p2").build());
        return manager;
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    //密码加密器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    //自定义配置
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //禁用csrf保护-前后端分离项目需要禁用，认证鉴权项目也要需要禁用
        http.csrf().disable();

        //请求url权限控制
        http.authorizeRequests()
                .anyRequest().authenticated();

        //用户登录控制
        http.formLogin()
                .failureHandler(new MyAuthenticationFailureHandler())
                .successHandler(new MyAuthenticationSuccessHandler());


        //会话控制
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //过滤器控制
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

    }
}
```

jwt校验过滤器放置在UsernamePasswordAuthenticationFilter 之前，一旦jwt校验通过之后，用户状态转为认证成功状态，那么UsernamePasswordAuthenticationFilter 就不会再执行校验逻辑了。

**步骤6：配置认证异常/鉴权异常**

```java
//异常控制
http.exceptionHandling()
    .accessDeniedHandler(new MyAccessDeniedHandler())
    .authenticationEntryPoint(new AuthenticationEntryPoint() {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {


            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write("has error：" + authException.getMessage());
        }
    })
    ;
```

**步骤7：使用pastman发起请求测试**

登录-带账号与密码

http://localhost:8080/jwt/login



鉴权-要设置token请求头

http://localhost:8080/depts/update



# 十二、项目改造

在原先RBAC项目基础上集成Spring Security + JWT 

改造前记住一个准则：

- **将自定义认证改成Spring Security 认证**
- **将自定义授权改成Spring Security 授权**



## 12.1 认证

**步骤1：启动项目，测试项目**

建库：rbac

导入数据：rbac.sql

修改mysql账号密码：application.yml     --   root/admin

修改redis密码：application.yml   有如果有配置



**步骤2：添加依赖**

```xml
<!--spring security 组件-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<!--引入jwt-->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.4.0</version>
</dependency>
```

**步骤3：配置SpringSecurityConfig**

```java

@EnableGlobalMethodSecurity(prePostEnabled=true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    //配置密码加密器
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

 		http.authorizeRequests()
                .antMatchers("/api/tokens").permitAll()
                .antMatchers("/api/verifyCodes").permitAll()
                .anyRequest().authenticated();

        
        
        //会话控制
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }
}

```

注释掉原先的登录拦截、权限拦截

```java
@Configuration
public class MvcJavaConfig implements WebMvcConfigurer {

/*    @Autowired
    private CheckLoginInterceptor loginInterceptor;
    @Autowired
    private CheckPermissionInterceptor permissionInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(loginInterceptor)
                .addPathPatterns("/**") // 拦截
                .excludePathPatterns("/api/login","/api/code","/api/logout","/favicon.ico"); // 排除
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/**") // 拦截
                .excludePathPatterns("/api/login","/api/code","/api/logout","/favicon.ico"); // 排除
    }*/
}

```

**步骤4：定义SpringSecurity 登录用户主体：LoginUser**

Spring Security 默认认证用户列表来自内存，而项目中用户信息则来自数据库，所以需要实现：UserDetailsService 接口，重写：loadUserByUsername 方法，将内存查询转换成数据库查询。



按照UserDetailsService 接口规范，loadUserByUsername 方法返回值是UserDetails，而RBAC项目登录用户主体是：Employee，很明显不适合，需要改造。这里改造方式：继承+组合

继承：新对象LoginUser，继承Spring Security 提供User对象

组合：将Employee 作为属性，组合到LoginUser类

```java
//为符合Spring security 认证授权逻辑封装认证对象
@Getter
@Setter
public class LoginUser extends User {
    //认证与授权主体
    private Employee employee;

    //参数1：登录账户 参数2：密码， 参数3：权限表达式列表
    public LoginUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public LoginUser(Employee employee, Collection<? extends GrantedAuthority> authorities) {
        super(employee.getName(), employee.getPassword(), authorities);
        this.employee = employee;
    }
}
```

**步骤5：定制项目认证服务类：UserDetailsServiceImpl**

注意：这里暂时不加载用户权限，后续鉴权时，再加

```java
@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private EmployeeMapper employeeMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //通过员工名查询员工对象
        Employee employee = employeeMapper.selectByUsername(username);

        if (employee == null){
            return null;
        }
        LoginUser loginUser = new LoginUser(employee, Collections.emptyList());
        return loginUser;
    }
}
```

对应sql：

```xml
<select id="selectByUsername" resultMap="BaseResultMap" >
    SELECT e.id,password,e.name,email,age,admin,d.id dept_id,d.name dept_name,d.sn dept_sn
    FROM employee e JOIN department d ON e.dept_id = d.id
    where e.name = #{username}
    order by e.id
</select>
```



**步骤6：改造TokenController登录接口**

```java
@RestController
@RequestMapping("/api/tokens")
public class TokenController {
    @Autowired
    private ITokenService tokenService;
    @PostMapping
    public R login(@RequestBody LoginVo vo){
        String token = tokenService.login(vo);
        return R.ok(token);
    }
    @DeleteMapping
    public R logout(@RequestHeader(name = "token") String token){
        tokenService.logout(token);
        return R.ok();
    }
}
```

**步骤7：在SpringSecurityConfig 添加 登录校验器**

```java
//认证器管理器-登录时会用到
@Bean
@Override
protected AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
}
```

**步骤8：改造TokenServiceImpl login方法**

```java
@Override
public String login(LoginVo vo) {
    //1.进行参数合法性校验
    if(StringUtils.isEmpty(vo.getName()) ||
       StringUtils.isEmpty(vo.getPassword()) ||
       StringUtils.isEmpty(vo.getUuid())){
        throw new BusinessException("非法参数");
    }
    //2.校验验证码是否正确
    String code = vo.getCode();
    String codeKey = RedisKey.VERIFYCODE_KEY_PREFIX+vo.getUuid();
    String redisCode = stringRedisTemplate.opsForValue().get(codeKey);
    if(StringUtils.isEmpty(redisCode)){
        throw new BusinessException("验证码过期，请重新获取");
    }
    if(!VerifyCodeUtil.verification(code,redisCode,true)){
        throw new BusinessException("验证码输入有误");
    }
    //3.校验账号密码
    /*Employee employee = employeeServcie.getByNameAndPassword(vo.getName(),vo.getPassword());
        if(employee==null){
            throw new BusinessException("账号密码有误");
        }*/

    LoginUser details = (LoginUser) userDetailsService.loadUserByUsername(vo.getName());
    Employee employee = details.getEmployee();

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
        details.getUsername(), details.getPassword(), details.getAuthorities());

    Authentication authenticate = authenticationManager.authenticate(token);


    //4.生成UUID,拼接key,将用户的信息存储到Redis中
    //String token = createToken(employee);
    //return token;

    String jwttoken = JWTUtils.createToken("login_user_name", vo.getName());
    return jwttoken;

}
```

**步骤9：自定义JWTUtils工具类**

```java

public class JWTUtils {

    public static  String scret = "abcdefjhijklmnopqrstuvwxyz";

    public static Long time = 7 * 24 * 60 * 60 * 1000L;  //7天

    public  static String createTokenMap(Map<String,String> map) {

        JWTCreator.Builder builder = JWT.create();
        for (Map.Entry<String, String> entry : map.entrySet())     {
            builder.withClaim(entry.getKey(), entry.getValue());

        }
        builder.withExpiresAt(new Date(System.currentTimeMillis() + time));
        String token = builder.sign(Algorithm.HMAC256(scret));
        return token;
    }
    public static String createToken(String key , String value) {

        JWTCreator.Builder builder = JWT.create();
        builder.withClaim(key,value);
        String token = builder.sign(Algorithm.HMAC256(scret));
        return token;
    }

    public  static String getToken(String token,String key){
        //先验证签名
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(scret)).build();
        //验证其他信息
        DecodedJWT verify = verifier.verify(token);
        String value = verify.getClaim(key).asString();
        return value;
    }
    public static  boolean isExpired(String token){
        //先验证签名
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(scret)).build();

        try {
            //验证其他信息
            DecodedJWT verify = verifier.verify(token);
            return true;
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
}
```

**步骤10：自定义jwt 过滤器**

```java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        //请求进入放行2个接口url

        String url = httpServletRequest.getRequestURI();
        if(url.startsWith("/api/tokens") || url.startsWith("/api/verifyCodes")){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        //jwt检查
        String jwttoken = httpServletRequest.getHeader("token");
        ObjectMapper mapper=new ObjectMapper();
        httpServletResponse.setContentType("application/json;charset=utf-8");

        if(!StringUtils.hasText(jwttoken)){
            httpServletResponse.getWriter().write(
                    mapper.writeValueAsString(R.fail(HttpStatus.INTERNAL_SERVER_ERROR.value(),"登录令牌必须传")));
            return;
        }

        if(!JWTUtils.isExpired(jwttoken)){
            httpServletResponse.getWriter().write(
                    mapper.writeValueAsString(R.fail(HttpStatus.INTERNAL_SERVER_ERROR.value(),"登录令牌失效")));
            return;
        }

        //正常，检查用户情况

        String username = JWTUtils.getToken(jwttoken, "login_user_name");
        UserDetails details = userDetailsService.loadUserByUsername(username);

        if(details == null){
            httpServletResponse.getWriter().write(
                    mapper.writeValueAsString(R.fail(HttpStatus.INTERNAL_SERVER_ERROR.value(),"登录令牌校验失败，请重新登录")));
            return;
        }

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken
                (details.getUsername(), details.getPassword(), details.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(token);

        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }
}

```

**步骤11：在SpringSecurityConfig配置jwt过滤器**

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();

 	http.authorizeRequests()
                .antMatchers("/api/tokens").permitAll()
                .antMatchers("/api/verifyCodes").permitAll()
                .anyRequest().authenticated();



    http.addFilterBefore(jwtAuthenticationTokenFilter,
                         UsernamePasswordAuthenticationFilter.class);
}
```

**步骤12：在MvcJavaConfig配置跨域过滤器**

重启后，返回登录页面，出现跨域异常，原因是注释原先的跨域允许配置，所以需要额外加

![image-20221111145746969](images/image-20221111145746969.png)

在MvcJavaConfig 中配置

```java
@Bean
public CorsFilter corsFilter() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    // 设置访问源地址
    config.addAllowedOrigin("*");
    // 设置访问源请求头
    config.addAllowedHeader("*");
    // 设置访问源请求方法
    config.addAllowedMethod("*");
    // 有效期 1800秒
    config.setMaxAge(1800L);
    // 添加映射路径，拦截一切请求
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    // 返回新的CorsFilter
    return new CorsFilter(source);
}
```

将上面的跨域允许过滤器加入Spring Security 过滤体系

注意：过滤器配置不能顺序不能乱

```java

@Autowired
private CorsFilter  corsFilter;

@Autowired
private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();

 	http.authorizeRequests()
                .antMatchers("/api/tokens").permitAll()
                .antMatchers("/api/verifyCodes").permitAll()
                .anyRequest().authenticated();



    http.addFilterBefore(jwtAuthenticationTokenFilter,
                         UsernamePasswordAuthenticationFilter.class);

    http.addFilterBefore(corsFilter,
                         JwtAuthenticationTokenFilter.class);

}
```

**步骤13：修改前端**

**方案1**：不修改，适合移动端项目

前端代码使用是sessionStorage存储jwt数据，适合单页应用



**方案2**：修改，适合PC端项目

前端代码使用是localStorage存储jwt数据，适合多页应用



sessionStorage  数据缓存在浏览器中， 浏览器关闭之后会消失， 无法多页签共享

localStorage  数据缓存在本地， 浏览器关闭之后不会消失， 可以多页签共享



**login/index.vue页面**

```js
async login() {
    const { data: res } = await this.$http.post("tokens", this.loginForm);
    if (res.code == 200) {
        //window.sessionStorage.setItem("token", res.data);
        window.localStorage.setItem("token", res.data);
        this.$router.push("/main");
    }
},
```

**main.js**

```js
// 请求拦截
axios.interceptors.request.use(function(request){
      //const token = window.sessionStorage.getItem("token");
      const token = window.localStorage.getItem("token");
      if(token){
        request.headers.token=token;
      }
      return request;
},function(err){
  return Promise.reject(err)
})
```

**router/index.js**

```js
// 挂载路由导航
router.beforeEach((to,from,next) =>{
	// to 将要访问的路径
	// from 代表从哪个路径跳转而来
	// next 是一个函数，表示放行
	//     next()  放行    next('/login')  强制跳转
	if(to.path==="/login") return next();
	const token=window.localStorage.getItem("token");
	if(token) return next();
	next("/login")
});
```

**main/index.vue**

```js
async logout(){
    // 发送请求退出
    const { data: res } = await this.$http.delete("tokens");
    if (res.code == 200) {
        //sessionStorage.clear();
        localStorage.clear();
        this.$router.push("/login");
    }
}
```



## 12.2 注销【拓展】

JWT一旦创建，在失效时间没到之前是不会销毁的，如果非要销毁，此时需要借助Redis

思路：

1>登录成功，将jwt添加到redis中，设置有效时间为jwt有效时间

2>注销时，将redis key 删除即可



## 12.3 授权

放弃原有授权与鉴权体系，使用Spring Security的

**步骤1：配置权限授权许可**

```java
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    ....
}
```

**步骤2：对部门/权限管理配置操作权限**

注意：其他接口同理，这里仅以部门与权限管理做测试

所以接口都贴上：@PreAuthorize("hasAnyAuthority('xxx:xxx')")

```java
@RestController
@RequestMapping("/api/departments")
public class DepartmentController {
    @Autowired
    private IDepartmentService departmentService;
    @GetMapping
    @RequirePermission(name = "部门列表",expression = "department:query")
    @PreAuthorize("hasAnyAuthority('department:query')")
    public R query(QueryObject qo){
        PageInfo<Department> pageInfo = departmentService.selectList(qo);
        return R.ok(new PageData(pageInfo));
    }
    @DeleteMapping("/{id}")
    @RequirePermission(name = "部门删除",expression = "department:delete")
    @PreAuthorize("hasAnyAuthority('department:delete')")
    public R delete(@PathVariable("id") Long id){
        departmentService.deleteByPrimaryKey(id);
        return R.ok();
    }
    @PostMapping
    @RequirePermission(name = "部门新增",expression = "department:add")
    @PreAuthorize("hasAnyAuthority('department:add')")
    public R add(@RequestBody Department department){
        departmentService.insert(department);
        return R.ok();
    }
    @PutMapping("/{id}")
    @RequirePermission(name = "部门更新",expression = "department:update")
    @PreAuthorize("hasAnyAuthority('department:update')")
    public R update(@PathVariable("id") Long id,@RequestBody Department department){
        departmentService.update(id,department);
        return R.ok();
    }

    @GetMapping(headers = QueryConstanst.CMD_LIST)
    public R list(){
        List<Department> departments = departmentService.selectAll();
        return R.ok(departments);
    }
}

```

**步骤3：改造：UserDetailsServiceImpl  加上用户权限**

```java
@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private EmployeeMapper employeeMapper;

    @Autowired
    private PermissionMapper permissionMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //通过员工名查询员工对象
        Employee employee = employeeMapper.selectByUsername(username);

        if (employee == null){
            return null;
        }

        //查询登录员工的权限
        List<GrantedAuthority> list = new ArrayList<>();
        if(employee.getAdmin()){
            // 如果是分配所有权限
            List<Permission> permissions = permissionMapper.selectAll();
            // 如果不是分配用户所拥有的权限
            for (Permission permission : permissions) {
                list.add(new SimpleGrantedAuthority(permission.getExpression()));
            }
        }else{
            //根据用户id 查询用户所拥有权限结合
            List<String> expressions = permissionMapper.queryPermissionByEId(employee.getId());
            for (String expression : expressions) {
                list.add(new SimpleGrantedAuthority(expression));
            }
        }

        LoginUser loginUser = new LoginUser(employee, Collections.emptyList());
        return loginUser;
    }
}
```



**步骤4：在统一异常类处理类，设置没有权限提示操作**

没有权限会抛出：AccessDeniedException 异常，所有需要单独处理

```java
/**
 * 统一异常处理
 */
@ControllerAdvice
public class ExceptionHandlerAdvice {
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public R handleException(Exception exception){
        exception.printStackTrace();
        return R.fail(exception.getMessage());
    }

    //权限
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseBody
    public R handleException(AccessDeniedException exception){
        exception.printStackTrace();
        return R.fail(HttpStatus.FORBIDDEN.value(),"没有权限访问");
    }
    
    //认证
    @ExceptionHandler(BadCredentialsException.class)
    @ResponseBody
    public R handleException(BadCredentialsException exception){
        exception.printStackTrace();
        return R.fail("账号或密码错误");
    }
}

```

**步骤5：测试准备**

1>创建一个test角色， 分配部门crud权限

2>给 **赵一明** 用户分配test角色

3>使用 **赵一明**  登录，分别方式部门与权限管理页面，观察结果



## 12.4 密码加密

到目前为止，登录密码都是明文，Spring Security 提供加密方式

**步骤1：在SpringSecurityConfig配置密码加密器**

```java
@Bean
public PasswordEncoder passwordEncoder(){
    //return NoOpPasswordEncoder.getInstance();
    return new BCryptPasswordEncoder();
}
```



**步骤2：设置密码认证器密码加密器**

```java
@Autowired
private UserDetailsService userDetailsService;
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
}
```

**步骤3：通过测试生成admin账号加密后密码**

```java
public class PwdDemo {

    public static void main(String[] args) {
        String password = "123";
        BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder();

        //加密：bcryptPasswordEncoder进行密码加密
        String encodedPassword = bcryptPasswordEncoder.encode(password);
        System.out.println("bcryptPasswordEncoder进行密码加密:"+encodedPassword);

        //解密：
        boolean flag = bcryptPasswordEncoder.matches(password, encodedPassword);
        //如果flag为true，则解密成功  false，则解密失败
        System.out.println("解密："+flag);
    }
}
```

**步骤4：修改TokenServiceImpl登录方法：login**

使用明文进行匹配

```java
UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
    details.getUsername(), /*details.getPassword()*/ vo.getPassword(), details.getAuthorities());

Authentication authenticate = authenticationManager.authenticate(token);
```



## 12.5 项目拓展

- 菜单权限

  当用户没有某个菜单权限，不显示该菜单。 比如：没有部门CRUD权限，就不显示部门菜单

  *![image-20240218103820826](images\image-20240218103820826.png)*

- 按钮权限

  当用户没有某个操作权限，对应的操作按钮也不显示。比如：没有部门删除权限，就不显示部门删除按钮

  *![image-20240218104018355](images\image-20240218104018355.png)*

- JWT vue解析

  前端没有做前端解析，课程尝试自己解析

















