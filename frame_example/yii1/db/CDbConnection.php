<?php
class CDbConnection extends CApplicationComponent
{
    // add function for pool
    public function release(){
        // USE_POOL 为开关 可以定义在index.php文件中
        if(defined("USE_POOL") && USE_POOL===true) {
            $transaction = $this->getCurrentTransaction();
            if(!empty($transaction)&&$transaction->getActive()){//事务里面不释放连接
                 return;
            }
            $this->_pdo->release();
        }
    }
}

