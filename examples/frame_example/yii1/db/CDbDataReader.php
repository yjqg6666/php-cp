<?php
class CDbDataReader extends CComponent implements Iterator, Countable
{
    private $_statement;
    private $_closed=false;
    private $_row;
    private $_index=-1;

    // add for pool
    private $_connection;

    /**
     * Constructor.
     * @param CDbCommand $command the command generating the query result
     */
    public function __construct(CDbCommand $command,$connection)
    {
        $this->_statement=$command->getPdoStatement();
        $this->_statement->setFetchMode(PDO::FETCH_ASSOC);
        $this->_connection = $connection;
    }
    public function read()
    {
        $data = $this->_statement->fetch();
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function readColumn($columnIndex)
    {
        $data = $this->_statement->fetchColumn($columnIndex);
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function readObject($className,$fields)
    {
        $data = $this->_statement->fetchObject($className,$fields);
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function readAll()
    {
        $data = $this->_statement->fetchAll();
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function nextResult()
    {
        // add for pool
        throw new Exception("cp not support foreach stmt");
        if(($result=$this->_statement->nextRowset())!==false)
            $this->_index=-1;
        return $result;
    }

    public function close()
    {
        $this->_statement->closeCursor();
        $this->_closed=true;
        // add for pool
        $this->_connection->release();
    }

    public function getRowCount()
    {
        $data = $this->_statement->rowCount();
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function getColumnCount()
    {
        $data = $this->_statement->columnCount();
        // add for pool
        $this->_connection->release();
        return $data;
    }

    public function current()
    {
        // add for pool
        throw new Exception("cp not support foreach stmt");
        return $this->_row;
    }

    public function next()
    {
        // add for pool
        throw new Exception("cp not support foreach stmt");
        $this->_row=$this->_statement->fetch();
        $this->_index++;
    }

}


