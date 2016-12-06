<?php
class CDbTransaction extends CComponent
{
    public function commit()
    {
        if($this->_active && $this->_connection->getActive())
        {
            Yii::trace('Committing transaction','system.db.CDbTransaction');
            $this->_connection->getPdoInstance()->commit();
            $this->_active=false;
            // add for pool
            $this->_connection->release();
        }
        else
            throw new CDbException(Yii::t('yii','CDbTransaction is inactive and cannot perform commit or roll back operations.  '));
    }

    public function rollback()
    {
        if($this->_active && $this->_connection->getActive())
        {
            Yii::trace('Rolling back transaction','system.db.CDbTransaction');
            $this->_connection->getPdoInstance()->rollBack();
            $this->_active=false;
            // add for pool
            $this->_connection->release();
        }
        else
            throw new CDbException(Yii::t('yii','CDbTransaction is inactive and cannot perform commit or roll back operations.'));
    }

}
