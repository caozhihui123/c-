#include "linuxheader.h"
#include <workflow/WFFacilities.h>
#include<wfrest/HttpServer.h>
#include <workflow/MySQLResult.h>
#include <workflow/MySQLMessage.h>
#include<wfrest/Json.h>
#include "FileUtil.h"
#include "UserInfo.h"
#include "Token.h"
static WFFacilities:: WaitGroup waitGroup(1);
void sigHandler(int num)
{
    waitGroup.done();
    fprintf(stderr,"waitgroup is done\n");
}
int main()
{
    signal(SIGINT,sigHandler);
   wfrest ::HttpServer server;
    server.GET("/file/upload",[](const wfrest::HttpReq *req,wfrest:: HttpResp *resp){
        resp->File("static/view/index.html");
    });
    server.POST("file/upload",[](const wfrest::HttpReq *req,wfrest:: HttpResp *resp){
        //读取文件内容，解析form-data类型的请求报文
        using Form = std::map<std::string,std::pair<std::string,std::string>>;
        Form &form=req->form();
        std::pair<std::string ,std::string> fileInfo =form["file"];
        std::string filepath = "tmp/" + fileInfo.first;
        int fd = open(filepath.c_str(),O_RDWR|O_CREAT,0666);
         if(fd < 0){
            resp->set_status_code("500");
            return;
        }
        //获取传文件的信息
        int ret = write(fd,fileInfo.second.c_str(),fileInfo.second.size());
        close(fd);
        
        std::string sql = "INSERT INTO cloudisk.tbl_file (file_sha1,file_name,file_size,file_addr,status) VALUES('" 
                   + FileUtil::sha1File(filepath.c_str()) + "','"
                   + fileInfo.first + "'," 
                   + std::to_string(fileInfo.second.size()) + ",'"
                   + filepath + "', 0);";
        resp->MySQL("mysql://root:123.czh@localhost",sql,[](wfrest::Json *pjson){
            fprintf(stderr,"out = %s\n", pjson->dump().c_str());
        });
        //fprintf(stderr,"sql = %s\n", sql.c_str());
         resp->set_status_code("302"); 
        resp->headers["Location"] = "/file/upload/success";
    });
       server.GET("/file/upload/success",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->String("Upload success");
    });

     server.GET("/file/download",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        // // /file/download?filehash=568691e2e4754643f16b0fd762b22811ff017110&filename=HEdge-YOLO.pdf&filesize=16884699
        auto fileInfo = req->query_list();
        std::string filesha1 = fileInfo["filehash"];
        std::string filename = fileInfo["filename"];
        int filesize = std::stoi(fileInfo["filesize"]);
        std::string filepath = "tmp/"+filename;

        // int fd = open(filepath.c_str(),O_RDONLY);
        // int size = lseek(fd,0,SEEK_END);
        // lseek(fd,0,SEEK_SET);
        // std::unique_ptr<char []> buf(new char[size]);
        // read(fd,buf.get(),size);

        // resp->append_output_body(buf.get(),size);
        // resp->headers["Content-Type"] = "application/octect-stream";
        // resp->headers["content-disposition"] = "attachment;filename="+filename;
        resp->set_status_code("302");
        resp->headers["Location"] = "http://192.168.89.128:1235/"+filename;
    });

    server.GET("/user/signup",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->File("static/view/signup.html");
    });
        server.POST("/user/signup",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp, SeriesWork *series){
        //1 按urlencoded的形式去解析post报文体
        std::map<std::string,std::string> &form_kv = req->form_kv();
        std::string username = form_kv["username"];
        std::string password = form_kv["password"];
        //2 把密码进行加密
        std::string salt = "12345678";
        char * encryptPassword = crypt(password.c_str(),salt.c_str());
        //fprintf(stderr,"encryptPassword = %s\n", encryptPassword);
        //3 把用户信息插入到数据库
        std::string sql = "INSERT INTO cloudisk.tbl_user (user_name,user_pwd) VALUES( '"+username + "','" + encryptPassword + "');";
        fprintf(stderr,"sql = %s\n", sql.c_str());
        // create_mysql_task
        auto mysqlTask = WFTaskFactory::create_mysql_task("mysql://root:123.czh@localhost",0,[](WFMySQLTask * mysqlTask){
            //4 回复一个SUCCESS给前端
            wfrest::HttpResp * resp2client = static_cast<wfrest::HttpResp *>(mysqlTask->user_data);
            if(mysqlTask->get_state() != WFT_STATE_SUCCESS){
                fprintf(stderr,"error msg:%s\n",WFGlobal::get_error_string(mysqlTask->get_state(), mysqlTask->get_error()));
                resp2client->append_output_body("FAIL",4);
                return;
            }

            protocol::MySQLResponse *resp = mysqlTask->get_resp();
            protocol::MySQLResultCursor cursor(resp);

            // 检查语法错误
            if(resp->get_packet_type() == MYSQL_PACKET_ERROR){
                fprintf(stderr,"error_code = %d msg = %s\n",resp->get_error_code(), resp->get_error_msg().c_str());
                resp2client->append_output_body("FAIL",4);
                return;
            }

            if(cursor.get_cursor_status() == MYSQL_STATUS_OK){
            //写指令，执行成功
                fprintf(stderr,"OK. %llu rows affected. %d warnings. insert_id = %llu.\n",
                    cursor.get_affected_rows(), cursor.get_warnings(), cursor.get_insert_id());
                if(cursor.get_affected_rows() == 1){
                    resp2client->append_output_body("SUCCESS",7);
                    return;
                }
            }
        });
        mysqlTask->get_req()->set_query(sql);
        mysqlTask->user_data = resp;
        // push_back
        series->push_back(mysqlTask);
    });
    server.GET("/static/view/signin.html",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->File("static/view/signin.html");
    });
    server.GET("/static/view/home.html",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->File("static/view/home.html");
    });
    server.GET("/static/js/auth.js",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->File("static/js/auth.js");
    });
    server.GET("/static/img/avatar.jpeg",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp){
        resp->File("static/img/avatar.jpeg");
    });
    server.POST("/user/signin",[](const wfrest::HttpReq *req, wfrest::HttpResp *resp, SeriesWork *series){
        //1 解析用户请求
        std::map<std::string, std::string> &form_kv = req->form_kv();
        std::string username = form_kv["username"];
        std::string password = form_kv["password"];
        //2 查询数据库
        std::string url = "mysql://root:123.czh@localhost";
        std::string sql = "SELECT user_pwd FROM cloudisk.tbl_user WHERE user_name = '" + username + "' LIMIT 1;";
        auto  readTask = WFTaskFactory::create_mysql_task(url,0,[](WFMySQLTask *readTask){
            //提取readTask的结果
            auto resp = readTask->get_resp();
            protocol::MySQLResultCursor cursor(resp);

            std::vector<std::vector<protocol::MySQLCell>> rows;
            cursor.fetch_all(rows);

            std::string nowPassword = rows[0][0].as_string();
            fprintf(stderr,"nowPassword = %s\n", nowPassword.c_str());
            
            UserInfo *userinfo = static_cast<UserInfo *>(series_of(readTask)->get_context());
            char * inPassword = crypt(userinfo->password.c_str(),"12345678");
            fprintf(stderr,"inPassword = %s\n", inPassword);
            if(strcmp(nowPassword.c_str(),inPassword) != 0){
                userinfo->resp->append_output_body("FAIL",4);
                return;
            }
            //3 生成一个token，存入数据库当中
            // 用户的信息->加密得到密文 拼接上 登录时间
            Token usertoken(userinfo->username,"12345678");
            //fprintf(stderr,"token = %s\n",usertoken.token.c_str());
            userinfo->token = usertoken.token;
            // 存入数据库当中
            std::string url = "mysql://root:123.czh@localhost";
            std::string sql = "REPLACE INTO cloudisk.tbl_user_token (user_name,user_token) VALUES ('" 
                + userinfo->username 
                + "', '" + usertoken.token + "');";
            auto writeTask = WFTaskFactory::create_mysql_task(url,0,[](WFMySQLTask *writeTask){
                UserInfo *userinfo = static_cast<UserInfo *>(series_of(writeTask)->get_context());
    //           userinfo->resp->set_status_code("302");
    // userinfo->resp->add_header_pair("Location", "/static/view/home.html");
                wfrest::Json uinfo;
                uinfo["Username"] = userinfo->username;
                uinfo["Token"] = userinfo->token;
                uinfo["Location"] = "/static/view/home.html";
                wfrest::Json respInfo;
                respInfo["code"] = 0;
                respInfo["msg"] = "OK";
                respInfo["data"] = uinfo;
                userinfo->resp->add_header_pair("Content-Type", "application/json; charset=utf-8");
                userinfo->resp->String(respInfo.dump());
            });
            writeTask->get_req()->set_query(sql);
            series_of(readTask)->push_back(writeTask);
        });
        readTask->get_req()->set_query(sql);
        series->push_back(readTask);
        UserInfo *userinfo = new UserInfo;
        userinfo->username = username;
        userinfo->password = password;
        userinfo->resp = resp;
        series->set_context(userinfo);
        // 在序列的回调函数当中释放
        series->set_callback([](const SeriesWork *series){
            // UserInfo *userinfo = static_cast<UserInfo *>(series->get_context());
            // delete userinfo;
            // fprintf(stderr,"userinfo is deleted\n");
        });
    });

   if(server.track().start(1234)==0){
    server.list_routes();
    waitGroup.wait();
    server.stop();
   }
   else{
    fprintf(stderr,"can not start server!\n");
    return -1;
   }
}