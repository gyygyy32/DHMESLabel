using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.Common;
using MySql.Data.MySqlClient;
using System.Data;
using System.Data.OracleClient;
using System.Data.SqlClient;
namespace MESLabel
{
    public class DBOperation
    {

        public DBOperation()
        {
                                   
        }
        private  DbDataAdapter _Adapter;
        private  DbDataAdapter Adapter(enuDBType DBType)
        {
            if (DBType == enuDBType.SqlConnection)
            {
                _Adapter = new SqlDataAdapter();

            }
            else if (DBType == enuDBType.MySqlConnection)
            {
                _Adapter = new MySqlDataAdapter();

            }
            else if (DBType ==enuDBType.NpgsqlConnection)//NpgsqlConnection
            {
                //_Adapter = new NpgsqlDataAdapter();

            }
            else//OracleConnection
            {
                _Adapter = new OracleDataAdapter();

            }
            return _Adapter;


        }
        private string _result = string.Empty;
        public  string Result 
        {
            get
            {
                return _result;
            }
            set
            {
                _result = value;
            }
        }

        public  string ServerIP ;
        public  string DB ;
        public  string DBUserName ;
        public  string DBPassWord ;
        public  string DBPort ;

        //private  NpgsqlConnection _NpgSqlconn = null;
        /// <summary>
        /// Npgsql正式环境
        /// </summary>
        //public  NpgsqlConnection NpgSqlconn
        //{
        //    get
        //    {

        //        _NpgSqlconn = (NpgsqlConnection)Conn(ServerIP, DBUserName, DBPassWord, "POSTGRESQL", DB, ref _result);
        //        return _NpgSqlconn;
        //    }

        //}
        private SqlConnection _Sqlconn = null;
        /// <summary>
        /// Sqlserver正式环境
        /// </summary>
        public SqlConnection Sqlconn
        {
            get
            {

                _Sqlconn = (SqlConnection)Conn(ServerIP, DBUserName, DBPassWord, enuDBType.SqlConnection, DB, ref _result);
                return _Sqlconn;
            }

        }

        private  MySqlConnection _MySqlconn = null;
        /// <summary>
        /// MySQL正式环境
        /// </summary>
        public  MySqlConnection MySqlconn
        {
            get
            {
                //_MySqlconn = (MySqlConnection)Conn("127.0.0.1", "mesadmin", "1qAZ2wSX", "MYSQL", "js_mes", ref Result);
                _MySqlconn = (MySqlConnection)Conn(ServerIP, DBUserName, DBPassWord, enuDBType.MySqlConnection, DB, ref _result);
                return _MySqlconn;
            }

        }
        private OracleConnection _Oracleconn = null;
        /// <summary>
        /// Oracle正式环境
        /// </summary>
        public OracleConnection Oracleconn
        {
            get
            {

                _Oracleconn = (OracleConnection)Conn(ServerIP, DBUserName, DBPassWord, enuDBType.OracleConnection, DB, ref _result);
                return _Oracleconn;
            }

        }

        #region "连接数据库"
        /// <summary>
        /// 功能描述: 连接数据库
        /// </summary>
        /// <param name="serverName">服务器名字</param>
        /// <param name="UserID">连接服务器的用户名</param>
        /// <param name="PassWord">连接服务器的密码</param>
        /// <param name="DBType">数据库类型（Sql Server or Oracle)</param>
        /// <param name="DefaultDB"> 函数执行结果（成功返回“Success”，失败返回错误信息）</param>
        /// <param name="Result"> 默认连接数据库（Sql Server）</param>
        /// <returns>返回一个打开的connection对象</returns>
        public  DbConnection Conn(string serverName, string UserID, string PassWord, enuDBType DBType, string DefaultDB, ref string Result)
        {
            string strconn;
            DbConnection s = null; ;
            //DBType = DBType.ToUpper();
            try
            {
                if (DBType == enuDBType.SqlConnection)
                {
                    strconn = "server=" + serverName + ";database=" + DefaultDB + ";uid=" + UserID + ";pwd=" + PassWord + ";Connection TimeOut=10";
                    if (s == null || s.ConnectionString == "")
                    {
                        s = new SqlConnection(strconn);
                    }

                    //如果OracleCon的状态不为打开状态，则将其Open
                    if (s.State != ConnectionState.Open)
                    {
                        s.Open();
                    }

                }
                else if (DBType == enuDBType.MySqlConnection)
                {
                    strconn = "server=" + serverName + ";database=" + DefaultDB + ";uid=" + UserID + ";pwd=" + PassWord + "; Connection TimeOut=10 ;Allow User Variables=True ;";
                    if (s == null || s.ConnectionString == "")
                    {
                        s = new MySqlConnection(strconn);
                    }

                    if (s.State != ConnectionState.Open)
                    {
                        s.Open();
                    }

                }
                else if (DBType == enuDBType.NpgsqlConnection)
                {

                    ////Server=192.168.1.100;Port=5432;UserId=mike;Password=secret;Database=mikedb;"
                    //strconn = "server=" + serverName + ";Port="+DBPort+";Database=" + DefaultDB + ";UserId=" + UserID + ";Password=" + PassWord + " ;TIMEOUT=15;";
                    //if (s == null || s.ConnectionString == "")
                    //{
                    //    s = new NpgsqlConnection(strconn);
                    //}

                    ////如果OracleCon的状态不为打开状态，则将其Open
                    //if (s.State != ConnectionState.Open)
                    //{
                    //    s.Open();
                    //}
                }
                else
                {
                    strconn = "Data Source=" + serverName + ";Persist Security Info=True;User ID=" + UserID + ";Password=" + PassWord + ";Unicode=True";
                    if (s == null || s.ConnectionString == "")
                    {
                        s = new OracleConnection(strconn);
                    }

                    //如果OracleCon的状态不为打开状态，则将其Open
                    if (s.State != ConnectionState.Open)
                    {
                        s.Open();
                    }

                }
                Result = "Success";


            }
            catch (Exception er)
            {
                Result = er.Message.ToString();
                _result = er.Message;
                throw;
            }
            
            return s;
             
        }

       
        #endregion

        #region "执行UPDATE、DELETE SQL语句或存储过程（可传递参数），并返回受影响的行数"
        /// <summary>
        ///  执行UPDATE、DELETE SQL语句或存储过程（可传递参数），并返回受影响的行数
        /// </summary>
        /// <param name="conn"> 要使用的Connectiong对象</param>
        /// <param name="sql"> 要执行的SQL语句或存储过程</param>
        /// <param name="cmdParameters">要使用的参数集合（可选）</param>
        /// <param name="cmdType"></param>
        /// <param name="Result">函数的执行结果（Success Or Fail）及DataBase中受影响的记录行数或错误描述</param>
        public  void ExecuteNonquery(DbConnection conn, string sql, DbParameter[] cmdParameters, CommandType cmdType, ref string Result)
        {
            DbCommand cmd = null;
            int RowCount;
            if (conn.State != ConnectionState.Open)
            {
                conn.Open();
            }
            cmd = conn.CreateCommand();
            cmd.Connection = conn;
            cmd.CommandTimeout = 30;
            cmd.CommandType = cmdType;
            cmd.CommandText = sql;
            DbTransaction tran = conn.BeginTransaction();
            cmd.Transaction = tran;

            if (cmdParameters != null)
            {
                foreach (DbParameter sqlPar in cmdParameters)
                {
                    cmd.Parameters.Add(sqlPar);
                }
            }
            try
            {
                //conn.BeginTransaction();
                //RowCount =cmd.ExecuteNonQuery();
                //Result = "Sueccess:" + RowCount.ToString() + " Rows Impact!";  这个会报错不支持并行事务
                //conn.BeginTransaction().Commit();


                RowCount = cmd.ExecuteNonQuery();
                Result = "Success:" + RowCount.ToString() + " Rows Impact!";
                tran.Commit();

            }
            catch (Exception er)
            {
                Result = "Fail:" + er.Message.ToString();
                _result = "Fail:" + er.Message.ToString();
                conn.BeginTransaction().Rollback();
                throw;
            }
            finally
            {
                cmd.Dispose();
                conn.Dispose();
            }


        }


        public  void ExecuteNonquery(DbConnection conn, string sql,ref string Result)
        {
            DbCommand cmd = null;
            int RowCount = 0;
            if (conn.State != ConnectionState.Open)
            {
                conn.Open();
            }
            cmd = conn.CreateCommand();
            cmd.Connection = conn;
            cmd.CommandTimeout = 30;
            cmd.CommandType = CommandType.Text;
            cmd.CommandText = sql;
            DbTransaction tran = conn.BeginTransaction();
            cmd.Transaction = tran;
            try
            {
                //conn.BeginTransaction();
                //RowCount =cmd.ExecuteNonQuery();
                //Result = "Sueccess:" + RowCount.ToString() + " Rows Impact!";
                //conn.BeginTransaction().Commit();这个会报错不支持并行事务


                RowCount = cmd.ExecuteNonQuery();
                Result = "Success:" + RowCount.ToString() + " Rows Impact!";
                tran.Commit();

            }
            catch (Exception er)
            {
                Result = "Fail:" + er.Message.ToString();
                _result = "Fail:" + er.Message.ToString();
                conn.BeginTransaction().Rollback();
                throw;
            }
            finally
            {
                cmd.Dispose();
                conn.Dispose();
            }


        }

        //public  void ExecuteNonquery(NpgsqlConnection conn, string sql, ref string Result)
        //{
        //    NpgsqlCommand cmd = null;
        //    int RowCount = 0;
        //    if (conn.State != ConnectionState.Open)
        //    {
        //        conn.Open();
        //    }
        //    cmd = conn.CreateCommand();
        //    cmd.Connection = conn;
        //    cmd.CommandTimeout = 30;
        //    cmd.CommandType = CommandType.Text;
        //    cmd.CommandText = sql;
        //    NpgsqlTransaction tran = conn.BeginTransaction();
        //    cmd.Transaction = tran;
        //    try
        //    {
        //        //conn.BeginTransaction();
        //        //RowCount =cmd.ExecuteNonQuery();
        //        //Result = "Sueccess:" + RowCount.ToString() + " Rows Impact!";
        //        //conn.BeginTransaction().Commit();这个会报错不支持并行事务


        //        RowCount = cmd.ExecuteNonQuery();
        //        Result = "Success:" + RowCount.ToString() + " Rows Impact!";
        //        tran.Commit();

        //    }
        //    catch (Exception er)
        //    {
        //        Result = "Fail:" + er.Message.ToString();
        //        _result = "Fail:" + er.Message.ToString();
        //        conn.BeginTransaction().Rollback();
        //        throw;
        //    }
        //    finally
        //    {
        //        cmd.Dispose();
        //        conn.Dispose();
        //    }


        //}

        #endregion

        #region "执行Select语句或存储过程（可传递参数），并返回一个DataTable对象"
        /// <summary>
        /// 执行Select语句或存储过程（可传递参数），并返回一个RecordSet对象
        /// </summary>
        /// <param name="conn">要使用的Connectiong对象</param>
        /// <param name="sql">要执行的SQL语句或存储过程</param>
        /// <param name="cmdParameters">要使用的参数集合（可选）</param>
        /// <param name="cmdType"></param>
        /// <returns></returns>
        public  DataTable ExecuteReader(DbConnection conn, string sql, DbParameter[] cmdParameters, CommandType cmdType)
        {
            DataTable dsDataSet = new DataTable();

            DbCommand cmd = null;
            if (conn.State != ConnectionState.Open)
            {
                conn.Open();
            }
            cmd = conn.CreateCommand();
            cmd.Connection = conn;
            cmd.CommandTimeout = 30;
            cmd.CommandType = cmdType;
            cmd.CommandText = sql;
            DbDataAdapter adtDataFill = Adapter((enuDBType)Enum.Parse(typeof(enuDBType),conn.GetType().Name.ToString()));

            if (cmdParameters != null)
            {
                foreach (DbParameter sqlPar in cmdParameters)
                {
                    cmd.Parameters.Add(sqlPar);
                }
            }

            try
            {

                adtDataFill.SelectCommand = cmd;
                adtDataFill.Fill(dsDataSet);




            }
            catch (Exception er)
            {
                _result = "Fail:" + er.Message.ToString();
                throw;
            }
            finally
            {
                cmd.Dispose();
                conn.Dispose();
            }
            if (dsDataSet.Rows.Count > 0)
            {
                return dsDataSet;
            }
            else
            {
                return null;
            }
        }
      
        /// <summary>
        /// return DataTable
        /// </summary>
        /// <param name="conn"></param>
        /// <param name="sql"></param>
        /// <returns></returns>
        public  DataTable ExecuteReader(DbConnection conn, string sql)
        {
            DataTable dsDataSet = new DataTable();

            DbCommand cmd = null;
            if (conn.State != ConnectionState.Open)
            {
                conn.Open();
            }
            cmd = conn.CreateCommand();
            cmd.Connection = conn;
            cmd.CommandTimeout = 30;
            cmd.CommandType = CommandType.Text;
            cmd.CommandText = sql;
            DbDataAdapter adtDataFill = Adapter((enuDBType)Enum.Parse(typeof(enuDBType),conn.GetType().Name.ToString()));

            try
            {

                adtDataFill.SelectCommand = cmd;
                adtDataFill.Fill(dsDataSet);




            }
            catch (Exception er)
            {
                _result = "Fail:" + er.Message.ToString();
                throw;
            }
            finally
            {
                cmd.Dispose();
                conn.Dispose();
            }

            if (dsDataSet.Rows.Count > 0)
            {
                return dsDataSet;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// return DataSet
        /// </summary>
        /// <param name="conn"></param>
        /// <param name="sql"></param>
        /// <returns></returns>
        public DataSet ExecuteDataSetReader(DbConnection conn, string sql)
        {
            DataSet dsDataSet = new DataSet();

            DbCommand cmd = null;
            if (conn.State != ConnectionState.Open)
            {
                conn.Open();
            }
            cmd = conn.CreateCommand();
            cmd.Connection = conn;
            cmd.CommandTimeout = 30;
            cmd.CommandType = CommandType.Text;
            cmd.CommandText = sql;
            DbDataAdapter adtDataFill = Adapter((enuDBType)Enum.Parse(typeof(enuDBType),conn.GetType().Name.ToString()));

            try
            {

                adtDataFill.SelectCommand = cmd;
                adtDataFill.Fill(dsDataSet);

                


            }
            catch (Exception er)
            {
                _result = "Fail:" + er.Message.ToString();
                throw;
            }
            finally
            {
                cmd.Dispose();
                conn.Dispose();
            }

             
                return dsDataSet;
            
              
        }

        /// <summary>
        /// 返回带表名称的DataSet
        /// </summary>
        /// <param name="conn"></param>
        /// <param name="sql"></param>
        /// <param name="TableNames">表名数组，要与sql对应</param>
        /// <returns></returns>
        public DataSet ExecuteDataSetReader(DbConnection conn, string sql, List<string> TableNames,ref string Result)
        {
            DataSet ds=new DataSet ();
            try
            {
                  ds = ExecuteDataSetReader(conn, sql);
            }
            catch
            {
                Result = _result;
                throw;
            }
            if (TableNames.Count != ds.Tables.Count)
            {
                 
                return null;
            }
            else
            {
                for (int i = 0; i < ds.Tables.Count; i++)
                {
                    ds.Tables[i].TableName = TableNames[i].ToString();
                } 
            }
            return ds;
        }
        #endregion


        #region 获取随机数
        /// <summary>
        ///  Random类是一个产生伪随机数字的类，它的构造函数有两种，
        ///一个是直接New Random()，另外一个是New Random(Int32)，
        ///前者是根据触发那刻的系统时间做为种子，来产生一个随机数字，
        ///后者可以自己设定触发的种子，一般都是用UnCheck((Int)DateTime.Now.Ticks)做为参数种子，
        ///因此如果计算机运行速度很快，如果触发Randm函数间隔时间很短，就有可能造成产生一样的随机数，
        ///因为伪随机的数字，在Random的内部产生机制中还是有一定规律的，并非是真正意义上的完全随机。
        /// </summary>
        /// <returns></returns>
        static  int GetRandomSeed()
        {
            byte[] bytes = new byte[4];
            System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rng.GetBytes(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }
        /// <summary>
        /// 从一段字符串中获取指定长度的随机组合数
        /// </summary>
        /// <param name="strChar">字符串</param>
        /// <param name="IntPassWordLength">指定随机数长度</param>
        /// <returns></returns>
        public  string randString(string strChar, int IntPassWordLength)
        {

            Random r = new Random(GetRandomSeed());     //把这个随机数封装起来供其他地方调用，这样重复的随机数就基本上不会存在了     
            string result = string.Empty;
            //生成一个8位长的随机字符，具体长度可以自己更改     
            for (int i = 0; i < IntPassWordLength; i++)
            {
                int m = r.Next(0, strChar.Length);  //这里下界是0，随机数可以取到，上界应该是75，因为随机数取不到上界，也就是最大74，符合我们的题意      
                string s = strChar.Substring(m, 1);
                result += s;
            }

            return result;
        }
        #endregion
    }

    public enum enuDBType
    {
        SqlConnection,
        MySqlConnection,
        NpgsqlConnection,
        OracleConnection,
    }
}
